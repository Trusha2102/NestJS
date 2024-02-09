import { Injectable } from '@nestjs/common';
import { MongoClient } from 'mongodb';
import * as dotenv from 'dotenv';

dotenv.config();

console.log("MONODB WAS CALLED")

@Injectable()
export class MongoDbService {
  private client: MongoClient;

  constructor() {
    // Initialize MongoDB connection
    this.client = new MongoClient(process.env.MONGODB_URI);
    this.client.connect();
  }

  async insertData(data: any) {
    // Insert data into MongoDB
    const db = this.client.db('ByteBase');
    await db.collection('users').insertOne(data);
  }
}