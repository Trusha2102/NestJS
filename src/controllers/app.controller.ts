import { Controller, Post, Body, HttpException, HttpStatus, Get } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../models/user.model';
import { User as UserDecorator } from '../decorators/user.decorator';
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';

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
  constructor(@InjectModel(User.name) private readonly userModel: Model<User>) {}

  @Post('/register')
  async register(@Body() createUserDto: CreateUserDto): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const createdUser = new this.userModel({
      username: createUserDto.username,
      password: hashedPassword,
    });
    return createdUser.save();
  }

  @Post('/login')
  async login(@Body() loginUserDto: LoginUserDto): Promise<{ token: string }> {
    const user = await this.userModel.findOne({ username: loginUserDto.username }).exec();
    if (!user) {
      throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
    }
    const isPasswordValid = await bcrypt.compare(loginUserDto.password, user.password);
    if (!isPasswordValid) {
      throw new HttpException('Invalid username or password', HttpStatus.UNAUTHORIZED);
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    return { token };
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
