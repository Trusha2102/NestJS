import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from '../../prisma/services/prisma.service';
import { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private readonly prismaService: PrismaService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: process.env.JWT_SECRET,
    });
  }

  async validate(payload: any, req: Request) {
    // Assuming PrismaService has a method to find user by ID
    const user = await this.prismaService.findUserById(payload.userId);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Attach the user ID to the request object
    req.user = { userId: payload.userId };

    return user;
  }
}
