import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { RolesController } from './controllers/role.controller';
import { RolesService } from './services/role.service';
import { Role, RoleSchema } from './models/role.model';

@Module({
  imports: [MongooseModule.forFeature([{ name: Role.name, schema: RoleSchema }])],
  controllers: [RolesController],
  providers: [RolesService],
})
export class RoleModule {}
