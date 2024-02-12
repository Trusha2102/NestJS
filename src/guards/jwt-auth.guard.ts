import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import * as jwt from 'jsonwebtoken';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private reflector: Reflector) { }

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean>('isPublic', [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }
    // Your existing authentication logic here
    // For example, you can check the request for a valid JWT token
    const request = context.switchToHttp().getRequest();
    const authToken = request.headers['authorization'];

    if (!authToken || !authToken.startsWith('Bearer ')) {
      return false;
    }

    const token = authToken.split(' ')[1]; // Extract the token from the Authorization header

    try {
      // Verify the JWT token
      const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
      if (decodedToken) {
        // Authentication successful
        return true;
      } else {
        // Invalid token
        return false;
      }
    } catch (error) {
      // Token verification failed
      return false;
    }
  }
}
