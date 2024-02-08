import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { MongooseModule } from '@nestjs/mongoose';
import { AppController } from './controllers/app.controller';
import { User, UserSchema } from './models/user.model';
import * as dotenv from 'dotenv';
import { AllExceptionsFilter } from './filters/all-exceptions.filter'; 

dotenv.config();
@Module({
  imports: [
    MongooseModule.forRoot(process.env.MONGODB_URI),
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter, //The All Exception Filter
    },
  ],
})
export class AppModule {}
