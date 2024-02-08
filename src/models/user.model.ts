import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema()
export class User extends Document {
  static findOne(arg0: { username: string; }) {
    throw new Error('Method not implemented.');
  }
  @Prop({ required: true, unique: true }) 
  username: string;

  @Prop({ required: true })
  password: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
