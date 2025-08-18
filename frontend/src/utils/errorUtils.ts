import { type ErrorCode, ERROR_MESSAGES } from '../constants/errors';

/**
 * Base application error class
 */
export class AppError extends Error {
  public readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string) {
    super(message);
    this.code = code;
    this.name = 'AppError';
  }
}

/**
 * Represents a network-related error
 */
export class NetworkError extends AppError {
  public readonly originalError?: unknown;

  constructor(originalError?: unknown) {
    super('NETWORK_FAILURE');
    this.originalError = originalError;
    this.name = 'NetworkError';
  }
}

/**
 * Represents a timeout error
 */
export class TimeoutError extends AppError {
  constructor() {
    super('CSRF_TIMEOUT_ERROR');
    this.name = 'TimeoutError';
  }
}

/**
 * Type guard to check if an error is an AppError
 */
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError;
}

/**
 * Type guard to check for specific error code
 */
export function isErrorCode(
  error: unknown,
  code: ErrorCode
): error is AppError {
  return isAppError(error) && error.code === code;
}

/**
 * Represents an Axios error with a specific response code
 */
interface AxiosErrorWithCode extends Error {
  isAxiosError: true;
  response?: {
    data?: {
      code?: string;
    };
  };
}

/**
 * Type guard to check if an error is an AxiosError with specific code
 * @param error Unknown error object
 * @param code Expected error code
 * @returns Type predicate indicating if error matches AxiosErrorWithCode
 */
export function isAxiosErrorWithCode(
  error: unknown,
  code: string
): error is AxiosErrorWithCode {
  if (!error || typeof error !== 'object') return false;

  const e = error as Record<string, unknown>;

  if (e.isAxiosError !== true) return false;

  if (!e.response || typeof e.response !== 'object') return false;

  const response = e.response as Record<string, unknown>;
  if (!response.data || typeof response.data !== 'object')
    return false;

  const data = response.data as Record<string, unknown>;
  return typeof data.code === 'string' && data.code === code;
}

/**
 * Type guard to check if an error has `isTimeout: true` property
 * @param error The error object to check
 * @returns `true` if the error has `isTimeout: true`, `false` otherwise
 */
export const hasIsTimeout = (error: unknown): boolean => {
  return (error as Record<string, unknown>)?.isTimeout === true;
};

export class AuthExpiredError extends AppError {
  constructor() {
    super(
      'AUTH_EXPIRED',
      'Authentication expired. Please log in again.'
    );
    this.name = 'AuthExpiredError';
  }
}

export class ServerError extends AppError {
  constructor() {
    super(
      'SERVER_ERROR',
      'Internal server error. Please try again later.'
    );
    this.name = 'ServerError';
  }
}

export class PermissionError extends AppError {
  constructor() {
    super(
      'PERMISSION_DENIED',
      'You do not have permission to perform this action.'
    );
    this.name = 'PermissionError';
  }
}

export class NotFoundError extends AppError {
  constructor() {
    super(
      'RESOURCE_NOT_FOUND',
      'The requested resource was not found.'
    );
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends AppError {
  constructor() {
    super(
      'RESOURCE_CONFLICT',
      'A resource with this identifier already exists.'
    );
    this.name = 'ConflictError';
  }
}

export class BadRequestError extends AppError {
  constructor() {
    super('BAD_REQUEST', 'Invalid request. Please check your input.');
    this.name = 'BadRequestError';
  }
}

export class RateLimitError extends AppError {
  constructor() {
    super(
      'RATE_LIMIT_EXCEEDED',
      'Too many requests. Please try again later.'
    );
    this.name = 'RateLimitError';
  }
}

export function getErrorMessage(error: unknown): string {
  if (isAppError(error)) {
    return ERROR_MESSAGES[error.code] || ERROR_MESSAGES.UNKNOWN_ERROR;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return ERROR_MESSAGES.UNKNOWN_ERROR;
}

/**
 * Represents a validation error with field-specific details
 */
export class ValidationError extends AppError {
  public readonly fields: Record<string, string>;

  constructor(fields: Record<string, string>) {
    super('VALIDATION_ERROR');
    this.name = 'ValidationError';
    this.fields = fields;
  }
}
