"""Tests for NestJSAnalyzer."""

from pathlib import Path

from devai.nestjs_analyzer import NestJSAnalyzer, NestJSFinding


INSECURE_NESTJS_APP = """\
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { Public } from '@nestjs/common';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({ origin: '*' });
  app.useGlobalPipes(new ValidationPipe({ whitelist: false, forbidNonWhitelisted: false }));

  JwtModule.register({
    secret: 'hardcoded_jwt_secret_value',
    signOptions: { expiresIn: '60s' },
  });

  TypeOrmModule.forRoot({
    type: 'postgres',
    synchronize: true,
    password: 'db_password_123',
  });

  const config = new DocumentBuilder().setTitle('API').build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(3000, '0.0.0.0');
}

bootstrap();
"""

INSECURE_NESTJS_CONTROLLER = """\
import { Controller, Get, Public } from '@nestjs/common';

@Controller('admin')
export class AdminController {
  @Public()
  @Get('users')
  getUsers() {
    return [];
  }

  @Get('debug/env')
  getEnv() {
    return process.env;
  }
}
"""

HARDENED_NESTJS_APP = """\
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);

  app.use(helmet());
  app.enableCors({
    origin: config.get<string>('ALLOWED_ORIGIN', 'https://example.com'),
    credentials: true,
  });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const port = config.get<number>('PORT', 3000);
  const host = config.get<string>('HOST', '127.0.0.1');
  await app.listen(port, host);
}

bootstrap();
"""


class TestNestJSAnalyzer:
    def test_detects_insecure_nestjs_app(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.ts").write_text(INSECURE_NESTJS_APP, encoding="utf-8")
        analyzer = NestJSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds
        assert "jwt_secret_hardcoded" in kinds
        assert "typeorm_synchronize" in kinds
        assert "swagger_exposed" in kinds
        assert "host_exposed" in kinds
        assert "validation_whitelist_false" in kinds
        assert analyzer.health_score() < 50.0

    def test_detects_public_admin_route(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"@nestjs/core": "^10.0.0", "@nestjs/common": "^10.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "admin.controller.ts").write_text(
            INSECURE_NESTJS_CONTROLLER, encoding="utf-8"
        )
        analyzer = NestJSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "public_admin_route" in kinds or "unprotected_admin_route" in kinds

    def test_hardened_nestjs_app_scores_well(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.ts").write_text(HARDENED_NESTJS_APP, encoding="utf-8")
        analyzer = NestJSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        assert findings == []
        assert analyzer.health_score() == 100.0

    def test_detects_via_package_json(self, tmp_path: Path):
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"@nestjs/core": "^10.0.0", "@nestjs/common": "^10.0.0"}}',
            encoding="utf-8",
        )
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.ts").write_text(
            "import { NestFactory } from '@nestjs/core';\n"
            "async function bootstrap() {\n"
            "  const app = await NestFactory.create({});\n"
            "  app.enableCors({ origin: '*' });\n"
            "}\n"
            "bootstrap();\n",
            encoding="utf-8",
        )
        analyzer = NestJSAnalyzer(str(tmp_path))
        findings = analyzer.analyze()
        kinds = {f.kind for f in findings}
        assert "cors_wildcard" in kinds

    def test_no_config_returns_empty(self, tmp_path: Path):
        analyzer = NestJSAnalyzer(str(tmp_path))
        assert analyzer.configs() == []
        assert analyzer.analyze() == []
        assert analyzer.health_score() == 100.0
        assert "no application" in analyzer.summary().lower()

    def test_finding_format(self):
        finding = NestJSFinding(
            kind="test",
            severity="high",
            message="test message",
            path="src/main.ts",
            lineno=1,
        )
        assert "[high]" in finding.format()
        assert "test message" in finding.format()

    def test_to_context(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.ts").write_text(HARDENED_NESTJS_APP, encoding="utf-8")
        analyzer = NestJSAnalyzer(str(tmp_path))
        context = analyzer.to_context()
        assert "NestJS application analysis" in context
        assert "health score" in context

    def test_generate_hardened_template(self):
        template = NestJSAnalyzer(".").generate_hardened_template()
        assert "ValidationPipe" in template
        assert "ConfigService" in template
        assert "helmet" in template
