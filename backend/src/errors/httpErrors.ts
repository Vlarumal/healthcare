export class HttpError extends Error {
  statusCode: number;
  code: string;
  details?: any;
  args: any[];

  constructor(statusCode: number, code: string, message: string, details?: any, ...args: any[]) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.args = args;
  }
}

export class BadRequestError extends HttpError {
  constructor(message = 'Bad Request', details?: any, ...args: any[]) {
    super(400, 'BAD_REQUEST', message, details, ...args);
  }
}

export class UnauthorizedError extends HttpError {
  constructor(message = 'Unauthorized', ...args: any[]) {
    super(401, 'UNAUTHORIZED', message, undefined, ...args);
  }
}

export class ForbiddenError extends HttpError {
  constructor(message = 'Forbidden', ...args: any[]) {
    super(403, 'FORBIDDEN', message, ...args);
  }
}

export class AccessDeniedError extends HttpError {
  constructor(message = 'Access Denied', ...args: any[]) {
    super(403, 'ACCESS_DENIED', message, ...args);
  }
}

export class NotFoundError extends HttpError {
  constructor(message = 'Not Found', ...args: any[]) {
    super(404, 'NOT_FOUND', message, undefined, ...args);
  }
}

export class InternalServerError extends HttpError {
  constructor(message = 'Internal Server Error', ...args: any[]) {
    super(500, 'INTERNAL_SERVER_ERROR', message, ...args);
  }
}

export class ConflictError extends HttpError {
  constructor(message = 'Conflict', ...args: any[]) {
    super(409, 'CONFLICT', message, undefined, ...args);
  }
}

export class CsrfValidationError extends ForbiddenError {
  constructor(message = 'CSRF token validation failed', ...args: any[]) {
    super(message, ...args);
    this.code = 'CSRF_VALIDATION_FAILED';
  }
}

export class InvalidTokenError extends UnauthorizedError {
  constructor(message = 'Invalid or expired token', ...args: any[]) {
    super(message, ...args);
    this.code = 'INVALID_TOKEN';
  }
}