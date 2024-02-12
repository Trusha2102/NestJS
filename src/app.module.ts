import { Module, UseGuards, SetMetadata } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './guards/jwt.strategy'; 
import { JwtAuthGuard } from './guards/jwt-auth.guard'; 
import { RolesGuard } from './guards/roles.guard'; 
import { AppController } from './controllers/app.controller';
import { User, UserSchema } from './models/user.model';
import * as dotenv from 'dotenv';
import { AllExceptionsFilter } from './filters/all-exceptions.filter'; 
import { RoleModule } from './role.module';
import { UserService } from './services/user.services';
import { PrismaModule } from '../prisma/services/prisma.module'; 

dotenv.config();

@Module({
  imports: [
    PrismaModule, // Use PrismaModule for database connection
    RoleModule,
    JwtModule.register({ secret: process.env.JWT_SECRET }), 
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter, 
    },
    JwtStrategy, 
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard, 
    },
    {
      provide: APP_GUARD,
      useClass: RolesGuard,
    },
  ],
})
export class AppModule {}
