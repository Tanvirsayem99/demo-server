import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';


async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: 'https://peaceful-haupia-504a3d.netlify.app', // Allow frontend
    credentials: true,              // If you're using cookies or auth headers
  });
  app.use(cookieParser());

  await app.listen(process.env.PORT ?? 8000);
}
bootstrap();
