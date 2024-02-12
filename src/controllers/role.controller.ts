import { Controller, Post, Get, Put, Body, Param, HttpException, HttpStatus, SetMetadata } from '@nestjs/common';
import { PrismaService } from '../../prisma/services/prisma.service';
import { Role } from '@prisma/client'; 

@Controller('roles')
export class RolesController {
  constructor(private prisma: PrismaService) {}

  @Post()
  @SetMetadata('isPublic', true)
  async createRole(@Body() roleData: { id: string; role: string }): Promise<Role> {
    try {
      const createdRole = await this.prisma.role.create({
        data: {
          id: roleData.id,
          role: roleData.role
        }
      });
      return createdRole;
    } catch (error) {
      console.error('Error creating role:', error);
      throw new HttpException('Unable to create role', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Put(':id')
  @SetMetadata('isPublic', true)
  async updateRole(@Param('id') id: string, @Body() roleData: Partial<Role>): Promise<Role> {
    try {
      const updatedRole = await this.prisma.role.update({
        where: { id },
        data: roleData
      });
      return updatedRole;
    } catch (error) {
      console.error('Error updating role:', error);
      throw new HttpException('Unable to update role', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get()
  @SetMetadata('isPublic', true)
  async getAllRoles(): Promise<Role[]> {
    try {
      const roles = await this.prisma.role.findMany(); 
      return roles;
    } catch (error) {
      console.error('Error fetching roles:', error);
      throw new HttpException('Unable to fetch roles', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
