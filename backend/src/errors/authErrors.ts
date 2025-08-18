import { LocalizedError } from './LocalizedError';

export class UserNotFoundError extends LocalizedError {
  constructor() {
    super('User not found');
    this.statusCode = 404;
    this.code = 'USER_NOT_FOUND';
  }
}

export class TokenRotationError extends LocalizedError {
  constructor(message: string = 'Token rotation failed') {
    super(message);
    this.statusCode = 401;
    this.code = 'TOKEN_ROTATION_ERROR';
  }
}