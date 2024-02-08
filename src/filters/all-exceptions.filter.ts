import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { MongooseError } from 'mongoose';
import { MongoError } from 'mongodb';
import { error } from 'console';

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const request = ctx.getRequest();

    // If an error has already been thrown by the API method, skip processing
    if (response.headersSent) {
      return;
    }

    let statusCode = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let errorCode = 'UNKNOWN_ERROR';
    let errorCategory = 'UNKNOWN';

    if (exception instanceof HttpException) {
      statusCode = exception.getStatus();
      message = exception.message;
      errorCode = 'HTTP_EXCEPTION';
      errorCategory = 'HTTP_EXCEPTION';
    } else if (exception instanceof MongooseError) {
      statusCode = HttpStatus.BAD_REQUEST;
      errorCode = 'MONGOOSE_ERROR';
      message = exception.message;
      errorCategory = 'MONGOOSE_ERROR'; 
    } else if (exception instanceof MongoError) {
      statusCode = HttpStatus.BAD_REQUEST;
      errorCode = 'MONGODB_ERROR';
      message = exception.message;
      errorCategory = 'MONGODB_ERROR'; 
    }

    response.status(statusCode).json({
      statusCode,
      timestamp: new Date().toISOString(),
      path: request.url,
      message,
      errorCode,
      errorCategory,
    });
  }

  private getMongooseErrorCategory(error: MongooseError): string {
    const errorMessage = error.message.toLowerCase();
    if (errorMessage.includes('validation')) {
      return 'VALIDATION_ERROR';
    }
    if (errorMessage.includes('duplicate key')) {
      return 'DUPLICATE_KEY_ERROR';
    }
    if (errorMessage.includes('null')) {
      return 'NULL_ERROR'; 
    }
    return 'OTHER';
  }

  private getMongoErrorCategory(error: MongoError): string {
    const errorCode = error.code;
    switch (errorCode) {
      case 11000:
        return 'DUPLICATE_KEY_ERROR';
      default:
        return 'OTHER';
    }
  }
}
