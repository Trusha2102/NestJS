import {
    Injectable,
    NestInterceptor,
    ExecutionContext,
    BadGatewayException,
    CallHandler,
  } from '@nestjs/common';
  import { Observable, throwError } from 'rxjs';
  import { catchError } from 'rxjs/operators';
  
console.log("The Error Interceptor was called and used")

  @Injectable()
  export class ErrorsInterceptor implements NestInterceptor {
    intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
        console.log('ErrorInterceptor executed!');
      return next
        .handle()
        .pipe(
          catchError(err => throwError(() => new BadGatewayException())),
        );
    }
  }
  