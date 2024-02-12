import { Controller, Post, Body, HttpException, HttpStatus, Get, Res, Param, SetMetadata, UseGuards, UseInterceptors, UsePipes } from '@nestjs/common';
import { Response } from 'express';
import { PrismaService } from '../../prisma/services/prisma.service';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import { TransformInterceptor } from '../interceptors/transform.interceptor';
import { ErrorsInterceptor } from '../interceptors/errors.interceptor';
import { IsNotEmpty, IsOptional } from 'class-validator';
import { ValidationPipe } from '../pipes/validation.pipe';


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


export class LoginUserDto {
  @IsNotEmpty()
  username: string;

  @IsNotEmpty()
  password: string;
  static username: any;
}

@Controller('users')
@UseInterceptors(TransformInterceptor, ErrorsInterceptor)
@UsePipes(new ValidationPipe())
export class AppController {
  constructor(private readonly prisma: PrismaService) { }

  @Post('/register')
  @SetMetadata('isPublic', true) // Mark this route as public
  async register(@Body() createUserDto: CreateUserDto, @Res() res: Response): Promise<void> {
    try {
      console.log('Received request to register user:', createUserDto);

      // Validate input
      if (!createUserDto.password) {
        console.log('Password is null');
        throw new HttpException('Password cannot be null', HttpStatus.BAD_REQUEST);
      }

      // // Hash the password
      // const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
      // console.log('Hashed password:', hashedPassword);

      // Create user with hashed password and provided role and assigned_to fields
      console.log('Creating user with data:', createUserDto);
      // Create user with provided password and other fields
      const createdUser = await this.prisma.createUser({
        username: createUserDto.username,
        password: createUserDto.password,
        role: createUserDto.role,
        assigned_to: createUserDto.assigned_to,
        id: createUserDto.id
      });
      console.log('User created:', createdUser);

      res.status(HttpStatus.CREATED).json(createdUser);
    } catch (error) {
      console.error('Error during user registration:', error);
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  @Post('/login')
  @SetMetadata('isPublic', true)
  @UsePipes(new ValidationPipe())
  async login(@Body() loginUserDto: LoginUserDto, @Res() res: Response): Promise<void> {
    try {
      // Check if username is missing
      if (!loginUserDto.username || !loginUserDto.password) {
        throw new HttpException('Username and password are required', HttpStatus.BAD_REQUEST);
      }

      // Find user in the database
      console.log('Attempting to find user:', loginUserDto.username);
      const user = await this.prisma.userService.findFirst(loginUserDto.username);

      // If user is not found, throw 401 Unauthorized error
      if (!user) {
        console.log('User not found:', loginUserDto.username);
        throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
      }

      // Compare passwords
      console.log('Comparing passwords for user:', loginUserDto.username);
      console.log('Stored hashed password:', user.password);
      console.log('Provided password:', loginUserDto.password);

      // Inside your login controller
      const providedPasswordHash = await bcrypt.hash(loginUserDto.password, 10);
      const storedHashedPassword = user.password;

      console.log("BOTH PASSWORDS:", providedPasswordHash, storedHashedPassword)

      // Compare hashed passwords
      const isPasswordValid = await bcrypt.compare(loginUserDto.password, storedHashedPassword);

      // If password is invalid, throw 401 Unauthorized error
      if (!isPasswordValid) {
        throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
      }

      console.log('Is password valid:', isPasswordValid);

      // If password is invalid, throw 401 Unauthorized error
      if (!isPasswordValid) {
        console.log('Invalid password for user:', loginUserDto.username);
        throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
      }

      // Generate JWT token
      console.log('Generating JWT token for user:', loginUserDto.username);
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      // Return token
      console.log('JWT token generated successfully for user:', loginUserDto.username);
      res.status(HttpStatus.OK).json({ token });
    } catch (error) {
      console.error('Error during login:', error);
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }


  @Get('/profile')
  @UseGuards(JwtAuthGuard) // Apply JWTAuthGuard for authentication
  async userProfile(@Param('id') id: string, @Res() res: Response): Promise<void> {
    try {
      const user = await this.prisma.userService.findFirst(LoginUserDto.username);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      res.status(HttpStatus.OK).json(user);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/assigned-user/:id')
  @UseGuards(JwtAuthGuard, RolesGuard) // Apply JWTAuthGuard and RolesGuard for authentication and authorization
  async getAssignedUser(@Param('id') id: string, @Res() res: Response): Promise<void> {
    try {
      const assignedUsers = await this.prisma.userService.findMany({ where: { assigned_to: id } });

      if (assignedUsers.length === 0) {
        throw new HttpException('No assigned users found', HttpStatus.NOT_FOUND);
      }

      res.status(HttpStatus.OK).json(assignedUsers);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Get('/user/:id')
  async getUserById(@Param('id') id: string, @Res() res: Response): Promise<void> {
    try {
      const user = await this.prisma.findUserById(id);

      if (!user) {
        throw new HttpException('User not found', HttpStatus.NOT_FOUND);
      }

      res.status(HttpStatus.OK).json(user);
    } catch (error) {
      throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
