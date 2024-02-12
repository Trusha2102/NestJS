// roles.guard.ts
import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PrismaService } from '../../prisma/services/prisma.service'; 

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector, private readonly prismaService: PrismaService) {} // Inject PrismaService

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>('roles', context.getHandler());
    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const userId = request.user.userId; // Assuming you have a way to retrieve user ID from request
    const user = await this.prismaService.findUserById(userId); // Assuming PrismaService has a method to find user by ID

    if (!user) {
      throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
    }

    // Check if user has the required role
    return roles.includes(user.role);
  }
}
