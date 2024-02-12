import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/services/prisma.module';
import { RolesController } from './controllers/role.controller';
import { PrismaService } from '../prisma/services/prisma.service'; 

@Module({
  imports: [PrismaModule], 
  controllers: [RolesController],
  providers: [PrismaService], 
})
export class RoleModule {}
