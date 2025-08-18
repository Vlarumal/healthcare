/**
 * Centralized error constants and types for consistent error handling
 */
export const ERROR_CODES = {
  CSRF_TIMEOUT_ERROR: 'CSRF_TIMEOUT_ERROR',
  NETWORK_FAILURE: 'NETWORK_FAILURE',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  AUTH_EXPIRED: 'AUTH_EXPIRED',
  SERVER_ERROR: 'SERVER_ERROR',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  RESOURCE_NOT_FOUND: 'RESOURCE_NOT_FOUND',
  RESOURCE_CONFLICT: 'RESOURCE_CONFLICT',
  BAD_REQUEST: 'BAD_REQUEST',
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  SESSION_EXPIRED: 'SESSION_EXPIRED',
  EMAIL_IN_USE: 'EMAIL_IN_USE',
  INVALID_TOKEN: 'INVALID_TOKEN',
  UNKNOWN_ERROR: 'UNKNOWN_ERROR'
} as const;

export type ErrorCode = keyof typeof ERROR_CODES;

export const ERROR_MESSAGES: Record<ErrorCode, string> = {
  CSRF_TIMEOUT_ERROR: 'Request timed out. Please try again.',
  NETWORK_FAILURE: 'Network error. Please check your connection and try again.',
  VALIDATION_ERROR: 'Validation failed. Please check your input.',
  AUTH_EXPIRED: 'Your session has expired. Please log in again.',
  SERVER_ERROR: 'Internal server error. Please try again later.',
  PERMISSION_DENIED: 'You do not have permission to perform this action.',
  RESOURCE_NOT_FOUND: 'The requested resource was not found.',
  RESOURCE_CONFLICT: 'A resource with this identifier already exists.',
  BAD_REQUEST: 'Invalid request. Please check your input.',
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later.',
  INVALID_CREDENTIALS: 'Invalid email or password.',
  SESSION_EXPIRED: 'Your session has expired. Please log in again.',
  EMAIL_IN_USE: 'Email address is already registered.',
  INVALID_TOKEN: 'Invalid or expired token.',
  UNKNOWN_ERROR: 'An unknown error occurred.'
};