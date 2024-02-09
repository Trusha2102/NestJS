import { Injectable, Logger } from '@nestjs/common';
import { Pool } from 'pg';
import * as dotenv from 'dotenv';

dotenv.config();

console.log("POSTGRES WAS CALLED")

@Injectable()
export class PostgresDbService {
  private pool: Pool;
  private readonly logger = new Logger(PostgresDbService.name);

  constructor() {
    // Initialize PostgreSQL connection
    this.pool = new Pool({
      user: process.env.POSTGRES_USER || 'user',
      host: process.env.POSTGRES_HOST || 'localhost',
      database: process.env.POSTGRES_DB || 'mydatabase',
      password: process.env.POSTGRES_PASSWORD || 'password',
      port: parseInt(process.env.POSTGRES_PORT, 10) || 5432,
    });
  }

  async insertData(data: any) {
    try {
      this.logger.log('Attempting to insert data into PostgreSQL...');
      // Insert data into PostgreSQL
      const client = await this.pool.connect();
      try {
        await client.query('BEGIN');
        await client.query('INSERT INTO mytable(data) VALUES($1)', [data]);
        await client.query('COMMIT');
        this.logger.log('Data inserted successfully into PostgreSQL');
      } catch (e) {
        await client.query('ROLLBACK');
        this.logger.error(`Error inserting data into PostgreSQL: ${e.message}`);
        throw e;
      } finally {
        client.release();
      }
    } catch (error) {
      this.logger.error(`Error connecting to PostgreSQL: ${error.message}`);
      throw error;
    }
  }
}
