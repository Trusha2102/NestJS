import { Injectable, NotFoundException, BadRequestException, ConflictException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Role } from '../models/role.model';

@Injectable()
export class RolesService {
  constructor(@InjectModel(Role.name) private readonly roleModel: Model<Role>) {}

  async create(roleData: Role): Promise<Role> {
    try {
    console.log("Recived Payload:", roleData)
      const existingRole = await this.roleModel.findOne({ role: roleData.role }).exec();
      if (existingRole) {
        throw new ConflictException('Role already exists.');
      }

      // If no duplicate role found, create and save the new role document
      const createdRole = new this.roleModel(roleData);
      return await createdRole.save();
    } catch (error) {
      // Handle other errors (e.g., database connection issues)
      throw new ConflictException('Could not create role.');
    }
  }

  async update(id: string, roleData: Partial<Role>): Promise<Role> {
    try {
      const updatedRole = await this.roleModel.findByIdAndUpdate(id, roleData, { new: true });
      if (!updatedRole) {
        throw new NotFoundException('Role not found.');
      }
      return updatedRole;
    } catch (error) {
      throw new BadRequestException('Could not update role.');
    }
  }

  async findAll(): Promise<Role[]> {
    try {
      return await this.roleModel.find().exec();
    } catch (error) {
      throw new Error('Could not fetch roles.');
    }
  }
}
