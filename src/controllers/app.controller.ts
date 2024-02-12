import { Controller, Post, Body, HttpException, HttpStatus, Get, Res, UseGuards, Param, SetMetadata, UseInterceptors } from '@nestjs/common';
import { Response } from 'express';
import { User } from '../models/user.model';
import { User as UserDecorator } from '../decorators/user.decorator';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { UserService } from '../services/user.services';
import { IsNotEmpty as IsNotEmptyValidator, IsOptional as IsOptionalValidator } from 'class-validator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { ErrorsInterceptor } from '../interceptors/errors.interceptor';

export class CreateUserDto {
  @IsNotEmptyValidator()
  username: string;

  @IsNotEmptyValidator()
  password: string;

  @IsNotEmptyValidator()
  role: string;

  @IsOptionalValidator()
  assigned_to: string;
}

class LoginUserDto {
  username: string;
  password: string;
}

@Controller()
@UseInterceptors(TransformInterceptor, ErrorsInterceptor)
export class AppController {
  constructor(private readonly userService: UserService) {}

  @Post('/register')
  @SetMetadata('isPublic', true) // Mark this route as public
  async register(@Body() createUserDto: CreateUserDto, @Res() res: Response): Promise<void> {
    try {
      // Validate input
      if (!createUserDto.password) {
        throw new HttpException('Password cannot be null', HttpStatus.BAD_REQUEST);
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);

      // Create user with hashed password and provided role and assigned_to fields
      const createdUser = await this.userService.createUserWithRole({
        ...createUserDto,
        password: hashedPassword,
      });

      res.status(HttpStatus.CREATED).json(createdUser);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('/login')
  @SetMetadata('isPublic', true) // Mark this route as public
  async login(@Body() loginUserDto: LoginUserDto, @Res() res: Response): Promise<void> {
    try {
      // Check if username is missing
      if (!loginUserDto.username || !loginUserDto.password) {
        throw new HttpException('Username and password are required', HttpStatus.BAD_REQUEST);
      }

      // Find user in the database
      const user = await this.userService.findByUsername(loginUserDto.username);

      // If user is not found, throw 401 Unauthorized error
      if (!user) {
        throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
      }

      // Compare passwords
      const isPasswordValid = await bcrypt.compare(loginUserDto.password, user.password);

      // If password is invalid, throw 401 Unauthorized error
      if (!isPasswordValid) {
        throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      // Return token
      res.status(HttpStatus.OK).json({ token });
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/profile')
  @UseGuards(JwtAuthGuard) // Apply JWTAuthGuard for authentication
  async userProfile(@UserDecorator() userData: any, @Res() res: Response): Promise<void> {
    try {
      if (!userData || !userData.userId) {
        throw new HttpException('Invalid or missing token', HttpStatus.UNAUTHORIZED);
      }

      const userId = userData.userId;

      // Fetch user profile using userService
      const user = await this.userService.findById(userId);

      // If user is not found, throw 404 Not Found error
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Return user profile
      res.status(HttpStatus.OK).json(user);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/assigned-user')
  @UseGuards(JwtAuthGuard, RolesGuard) // Apply JWTAuthGuard and RolesGuard for authentication and authorization
  async getAssignedUser(@UserDecorator() userData: any, @Res() res: Response): Promise<void> {
    try {
      if (!userData || !userData.userId) {
        throw new HttpException('Invalid or missing token', HttpStatus.UNAUTHORIZED);
      }

      const userId = userData.userId;

      // Fetch all users
      const allUsers = await this.userService.findAll();

      // Filter users based on assigned_to field
      const assignedUsers = allUsers.filter(user => user.assigned_to === userId);

      // If no assigned users found, throw 404 Not Found error
      if (assignedUsers.length === 0) {
        throw new HttpException('No assigned users found', HttpStatus.NOT_FOUND);
      }

      // Return assigned user details
      res.status(HttpStatus.OK).json(assignedUsers);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/user/:id')
  async getUserById(@Param('id') id: string, @UserDecorator() userData: any, @Res() res: Response): Promise<void> {
    try {
      if (!userData || !userData.userId || userData.userId !== id) {
        throw new HttpException('Unauthorized', HttpStatus.UNAUTHORIZED);
      }

      // Fetch user by id using userService
      const user = await this.userService.findById(id);

      // If user is not found, throw 404 Not Found error
      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      // Return user details
      res.status(HttpStatus.OK).json(user);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
