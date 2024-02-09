import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from '../models/user.model';

@Injectable()
export class UserService {
  constructor(@InjectModel(User.name) private readonly userModel: Model<User>) {}

  async createUserWithRole(userData: any): Promise<User> {
    // Create user
    const createdUser = new this.userModel(userData);
    return await createdUser.save();
  }

  async findByUsername(username: string): Promise<User | null> {
    return this.userModel.findOne({ username }).exec();
  }

  async findById(userId: string): Promise<User | null> {
    return this.userModel.findById(userId).exec();
  }

  async findAll(userId?: any): Promise<User[]> {
    if (userId) {
      // Perform filtering based on userId if provided
      return await this.userModel.find({ assigned_to: userId }).exec();
    } else {
      // Return all users if userId is not provided
      return await this.userModel.find().exec();
    }
  }
}
