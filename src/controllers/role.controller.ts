import { Controller, Post, Body, Put, Param, HttpException, HttpStatus, Get } from '@nestjs/common';
import { RolesService } from '../services/role.service';
import { Role } from '../models/role.model';

@Controller('roles')
export class RolesController {
  constructor(private readonly rolesService: RolesService) {}

  @Post()
  async createRole(@Body() roleData: Role): Promise<Role> {
    try {
      const createdRole = await this.rolesService.create(roleData);
      return createdRole;
    } catch (error) {
      // Handle the error gracefully
      console.error('Error creating role:', error);
      throw new HttpException('Unable to create role', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Put(':id')
  async updateRole(@Param('id') id: string, @Body() roleData: Partial<Role>): Promise<Role> {
    const updatedRole = await this.rolesService.update(id, roleData);
    return updatedRole;
  }

  @Get()
  async getAllRoles(): Promise<Role[]> {
    try {
      const roles = await this.rolesService.findAll();
      return roles;
    } catch (error) {
      console.error('Error fetching roles:', error);
      throw new HttpException('Unable to fetch roles', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
