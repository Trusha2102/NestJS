import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaClient, Role, User } from '@prisma/client';
import { IsNotEmpty, IsOptional } from 'class-validator';
import * as bcrypt from 'bcrypt';
import { createECDH } from 'crypto';

// Define custom UserCreateInput type
interface UserCreateInput {
  [x: string]: any;
  username: string;
  password: string;
  role: string;
  assigned_to?: string;
}

export class CreateUserDto {
  @IsOptional()
  id: string;

  @IsNotEmpty()
  username: string;

  @IsNotEmpty()
  password: string;

  @IsNotEmpty()
  role: string;

  @IsOptional()
  assigned_to: string;
}

@Injectable()
export class PrismaService {
  private readonly prisma: PrismaClient;

  constructor() {
    this.prisma = new PrismaClient();
    this.prisma.$connect(); // Connect to the database

    console.log('Prisma service initialized and connected to the database');
  }
  //For USER
  userService = {
    findMany: async (params: { where: { assigned_to: string } }): Promise<User[]> => {
      return await this.prisma.user.findMany(params);
    },
    findFirst: async (username: string): Promise<User | null> => {
      return this.prisma.user.findFirst({
        where: { username: username },
      });
    }
  };

async createUser(createUserDto: CreateUserDto) {
    try {
        const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
        const userData: UserCreateInput = {
            username: createUserDto.username,
            password: hashedPassword,
            role: createUserDto.role,
            assigned_to: createUserDto.assigned_to,
            id: createUserDto.id
        };

        console.log("THIS IS THE USER DATA FROM SERVICES", userData);

        // Create the user without the id property
        return await this.prisma.user.create({
            data: userData as any, 
        });
    } catch (error) {
        console.error('Error during user registration:', error);
        throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}


  getPrisma(): PrismaClient {
    return this.prisma;
  }

  async findUserById(id: string): Promise<User | null> {
    return await this.prisma.user.findUnique({ where: { id } });
  }

  //For ROLES
  get role() {
    return this.prisma.role;
  }

  async createRole(roleData: { id: string; role: string }): Promise<Role> {
    const { id, role } = roleData;
    const createdRole = await this.prisma.role.create({ data: { id, role } });
    return createdRole;
  }

  async updateRole(id: string, roleData: Partial<Role>): Promise<Role> {
    return await this.prisma.role.update({ where: { id }, data: roleData });
  }

  async findAllRoles(): Promise<Role[]> {
    return await this.prisma.role.findMany();
  }

  async findRoleById(id: string): Promise<Role | null> {
    return await this.prisma.role.findUnique({ where: { id } });
  }

}
