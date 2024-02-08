import { Controller, Post, Body, HttpException, HttpStatus, Get, Res } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Response } from 'express'; 
import { Model } from 'mongoose';
import { User } from '../models/user.model';
import { User as UserDecorator } from '../decorators/user.decorator';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { BadRequestException } from '@nestjs/common';

class CreateUserDto {
  username: string;
  password: string;
}

class LoginUserDto {
  username: string;
  password: string;
}

@Controller()
export class AppController {
  userService: any;
  constructor(@InjectModel(User.name) private readonly userModel: Model<User>) {}

  @Post('/register')
  async register(@Body() createUserDto: CreateUserDto, @Res() res: Response): Promise<void> {
    try {
      if (!createUserDto.password) {
        const errorCode = 'PASSWORD_NULL';
        const message = 'Password cannot be null';
        res.status(HttpStatus.BAD_REQUEST).json({ errorCode, message });
        return;
      }

      const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
      const createdUser = new this.userModel({
        username: createUserDto.username,
        password: hashedPassword,
      });
      const savedUser = await createdUser.save();
      res.status(HttpStatus.CREATED).json(savedUser);
    } catch (error) {
      const errorCode = 'UNKNOWN_ERROR';
      const message = error.message;
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ errorCode, message });
    }
  }

  @Post('/login')
  async login(@Body() loginUserDto: LoginUserDto, @Res() res: Response): Promise<void> {
    try {
      // Check if username is missing
      if (!loginUserDto.username) {
        throw new HttpException('Username is required', HttpStatus.BAD_REQUEST);
      }

      // Check if password is missing
      if (!loginUserDto.password) {
        throw new HttpException('Password is required', HttpStatus.BAD_REQUEST);
      }
      // Find user in the database
      const user = await this.userModel.findOne({ username: loginUserDto.username }).exec();

      // If user is not found, throw 401 Unauthorized error
      if (!user) {
        const errorCode = 'INVALID_CREDENTIALS';
        const message = 'Invalid username or password';
        res.status(HttpStatus.UNAUTHORIZED).json({ errorCode, message });
        return;
      }

      // Compare passwords
      const isPasswordValid = await bcrypt.compare(loginUserDto.password, user.password);

      // If password is invalid, throw 401 Unauthorized error
      if (!isPasswordValid) {
        const errorCode = 'INVALID_CREDENTIALS';
        const message = 'Invalid username or password';
        res.status(HttpStatus.UNAUTHORIZED).json({ errorCode, message });
        return;
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

      // Return token
      res.status(HttpStatus.OK).json({ token });
    } catch (error) {
      const errorCode = 'UNKNOWN_ERROR';
      const message = error.message;
      res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ errorCode, message });
    }
  }

  @Get('/profile')
  async userProfile(@UserDecorator() userData: any): Promise<User> {
    if (!userData) {
      throw new HttpException('Invalid or missing token', HttpStatus.UNAUTHORIZED);
    }

    const userId = userData.userId;


    // Fetch user data from the database based on the user ID
    return this.userModel.findById(userId);
  }
}
