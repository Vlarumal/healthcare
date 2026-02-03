/**
 * Test Helpers
 * 
 * Provides utility functions for backend testing including
 * JWT generation, mock request/response creation, and assertion helpers.
 * @module test-utils/testHelpers
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { MockAuthUser } from './mockData';

// ============================================================================
// JWT Token Generation
// ============================================================================

/**
 * Default JWT secret for testing
 * In production, this should come from environment variables
 */
const TEST_JWT_SECRET = 'test-secret-key-for-jwt-signing-only';

/**
 * Default test keys for RS256 algorithm
 * These are minimal keys for testing purposes only
 */
// const TEST_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
// MIIEpAIBAAKCAQEAxgNSPM+TDyxKjXtB2ZFJV9tHGDPQSjz8rHc3QVJRbu8Uj3g5
// eI2gK+Pxnkz7rY6qG7P4eGMLnYvHjGQlT4pS5cX+Y7J0v8O7m7sF+J8Pq2Q8L3W9
// M5HnF7K2L8M9Q2R4T6Y8U0I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R
// T5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2
// F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0
// V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7
// U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6
// -----END RSA PRIVATE KEY-----`;

// const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxgNSPM+TDyxKjXtB2ZFJ
// V9tHGDPQSjz8rHc3QVJRbu8Uj3g5eI2gK+Pxnkz7rY6qG7P4eGMLnYvHjGQlT4pS
// 5cX+Y7J0v8O7m7sF+J8Pq2Q8L3W9M5HnF7K2L8M9Q2R4T6Y8U0I2O4P6A8S0D2F4
// G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3RT5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8
// B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E
// 3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8
// S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L
// 4M6N8B0V2C4X5Z7Q9W1E3R5Y7U9I2O4P6A8S0D2F4G6H8J0K2L4M6N8B0V2C4X5Z7
// -----END PUBLIC KEY-----`;

/**
 * Default token payload for testing
 */
const DEFAULT_TOKEN_PAYLOAD = {
  tokenVersionHash: 'mock-token-version-hash',
  fingerprint: 'mock-fingerprint',
  jti: 'mock-jti-123',
};

/**
 * Generates a mock fingerprint hash for JWT tokens
 * 
 * @param userAgent - Optional user agent string
 * @param ip - Optional IP address
 * @returns Fingerprint hash string
 */
export function generateMockFingerprint(
  userAgent: string = 'Mozilla/5.0 (Test)',
  ip: string = '127.0.0.1'
): string {
  return crypto
    .createHmac('sha256', 'test-secret')
    .update(`${userAgent}:${ip}`)
    .digest('hex');
}

/**
 * Creates a valid JWT for testing authentication
 * 
 * @param user - The user to create the token for
 * @param options - Optional token configuration
 * @returns JWT token string
 */
export function generateAuthToken(
  user: MockAuthUser,
  options: {
    secret?: string;
    expiresIn?: string;
    includeFingerprint?: boolean;
    userAgent?: string;
    ip?: string;
  } = {}
): string {
  const {
    secret = TEST_JWT_SECRET,
    expiresIn = '1h',
    includeFingerprint = true,
    userAgent = 'Mozilla/5.0 (Test)',
    ip = '127.0.0.1',
  } = options;

  const payload = {
    userId: user.id,
    role: user.role,
    passwordVersion: user.passwordVersion,
    ...DEFAULT_TOKEN_PAYLOAD,
    ...(includeFingerprint && {
      fingerprint: generateMockFingerprint(userAgent, ip),
    }),
  };

  const signOptions: jwt.SignOptions = { expiresIn: expiresIn as jwt.SignOptions['expiresIn'] };
  return jwt.sign(payload, secret, signOptions);
}

/**
 * Creates a valid refresh token for testing
 *
 * @param user - The user to create the refresh token for
 * @param options - Optional token configuration
 * @returns Refresh token string
 */
export function generateRefreshToken(
  user: MockAuthUser,
  options: {
    secret?: string;
    expiresIn?: string;
  } = {}
): string {
  const {
    secret = TEST_JWT_SECRET,
    expiresIn = '7d',
  } = options;

  const payload = {
    userId: user.id,
    role: user.role,
    passwordVersion: user.passwordVersion,
    type: 'refresh',
    jti: `refresh-jti-${Date.now()}`,
  };

  const signOptions: jwt.SignOptions = { expiresIn: expiresIn as jwt.SignOptions['expiresIn'] };
  return jwt.sign(payload, secret, signOptions);
}

/**
 * Decodes a JWT token without verifying it
 * 
 * @param token - The JWT token to decode
 * @returns Decoded token payload or null
 */
export function decodeAuthToken(token: string): any {
  return jwt.decode(token);
}

// ============================================================================
// Mock Request/Response Creation
// ============================================================================

/**
 * Mock cookie options
 */
interface MockCookieOptions {
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  maxAge?: number;
  path?: string;
}

/**
 * Creates a mock Express request object
 * 
 * @param overrides - Properties to override in the request
 * @returns Mock Express request object
 */
export function createMockRequest(overrides: Partial<Request> = {}): Request {
  const cookies: Record<string, string> = overrides.cookies || {};
  const headers: Record<string, string> = (overrides.headers as Record<string, string>) || {};
  const query: Record<string, any> = (overrides.query as Record<string, any>) || {};
  const params: Record<string, string> = (overrides.params as Record<string, string>) || {};
  const body: Record<string, any> = (overrides.body as Record<string, any>) || {};

  return {
    headers,
    body,
    query,
    params,
    cookies,
    ip: '127.0.0.1',
    method: 'GET',
    url: '/',
    path: '/',
    protocol: 'http',
    secure: false,
    hostname: 'localhost',
    fresh: false,
    stale: true,
    xhr: false,
    get: jest.fn((header: string) => headers[header.toLowerCase()]),
    header: jest.fn((header: string) => headers[header.toLowerCase()]),
    accepts: jest.fn().mockReturnValue(true),
    acceptsCharsets: jest.fn().mockReturnValue(true),
    acceptsEncodings: jest.fn().mockReturnValue(true),
    acceptsLanguages: jest.fn().mockReturnValue(true),
    range: jest.fn().mockReturnValue(undefined),
    param: jest.fn((name: string) => params[name]),
    is: jest.fn().mockReturnValue(false),
    ...overrides,
  } as unknown as Request;
}

/**
 * Creates a mock authenticated Express request
 * 
 * @param user - The authenticated user
 * @param overrides - Additional properties to override
 * @returns Mock Express request with user attached
 */
export function createMockAuthRequest(
  user: MockAuthUser,
  overrides: Partial<Request> = {}
): Request {
  const req = createMockRequest({
    ...overrides,
    headers: {
      authorization: `Bearer ${generateAuthToken(user)}`,
      ...((overrides.headers as Record<string, string>) || {}),
    },
  });

  // Attach user to request (as done by auth middleware)
  (req as any).user = {
    id: user.id,
    role: user.role,
  };

  return req;
}

/**
 * Creates a mock Express response object
 * 
 * @returns Mock Express response object with chainable methods
 */
export function createMockResponse(): Response {
  const cookies: Record<string, { value: string; options: MockCookieOptions }> = {};
  let statusCode = 200;
  let jsonData: any = {};
  let responseSent = false;

  const res: any = {
    statusCode,
    locals: {},
    headersSent: false,
    
    status: jest.fn((code: number) => {
      statusCode = code;
      res.statusCode = code;
      return res;
    }),
    
    json: jest.fn((data: any) => {
      jsonData = data;
      responseSent = true;
      return res;
    }),
    
    send: jest.fn(() => {
      responseSent = true;
      return res;
    }),
    
    cookie: jest.fn((name: string, value: string, options: MockCookieOptions = {}) => {
      cookies[name] = { value, options };
      return res;
    }),
    
    clearCookie: jest.fn((name: string,) => {
      delete cookies[name];
      return res;
    }),
    
    set: jest.fn((field: string | Record<string, string>, value?: string) => {
      if (typeof field === 'string' && value) {
        res.setHeader(field, value);
      }
      return res;
    }),
    
    setHeader: jest.fn(() => {
      // Implementation for setting headers
      return res;
    }),
    
    getHeader: jest.fn((name: string) => {
      return res.headers?.[name];
    }),
    
    removeHeader: jest.fn((name: string) => {
      if (res.headers) {
        delete res.headers[name];
      }
      return res;
    }),
    
    redirect: jest.fn(() => {
      responseSent = true;
      return res;
    }),
    
    sendStatus: jest.fn((code: number) => {
      statusCode = code;
      res.statusCode = code;
      responseSent = true;
      return res;
    }),
    
    type: jest.fn(() => {
      return res;
    }),
    
    format: jest.fn((obj: Record<string, () => void>) => {
      if (obj.json) obj.json();
      return res;
    }),
    
    end: jest.fn(() => {
      responseSent = true;
      return res;
    }),
    
    jsonp: jest.fn((data: any) => {
      jsonData = data;
      responseSent = true;
      return res;
    }),
    
    location: jest.fn(() => {
      return res;
    }),
    
    // Utility methods for tests
    _getStatusCode: () => statusCode,
    _getJSONData: () => jsonData,
    _getCookies: () => cookies,
    _isResponseSent: () => responseSent,
  };

  return res as Response;
}

/**
 * Creates a mock Express next function
 * 
 * @returns Mock next function that tracks calls
 */
export function createMockNext(): NextFunction & { mock: { calls: any[][] } } {
  const calls: any[][] = [];
  
  const nextFn: any = jest.fn((err?: any) => {
    calls.push([err]);
  });
  
  nextFn.mock = { calls };
  
  return nextFn;
}

// ============================================================================
// Error Assertion Helpers
// ============================================================================

/**
 * Expected error response structure
 */
interface ErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
    details?: any;
  };
}

/**
 * Asserts that a response matches an expected error structure
 * 
 * @param response - The response to check (from supertest or mock response)
 * @param status - Expected HTTP status code
 * @param code - Expected error code
 * @param message - Optional expected error message (substring match)
 */
export function expectErrorResponse(
  response: { status: number; body: ErrorResponse } | MockResponse,
  status: number,
  code: string,
  message?: string
): void {
  let actualStatus: number;
  let body: ErrorResponse;

  if ('_getStatusCode' in response) {
    // It's a mock response
    actualStatus = response._getStatusCode();
    body = response._getJSONData();
  } else {
    // It's a supertest response
    actualStatus = response.status;
    body = response.body;
  }

  expect(actualStatus).toBe(status);
  expect(body).toHaveProperty('success', false);
  expect(body.error).toBeDefined();
  expect(body.error.code).toBe(code);
  
  if (message) {
    expect(body.error.message).toContain(message);
  }
}

/**
 * Type guard to check if a response is an error response
 * 
 * @param body - Response body to check
 * @returns True if body is an error response
 */
export function isErrorResponse(body: any): body is ErrorResponse {
  return (
    body &&
    body.success === false &&
    body.error &&
    typeof body.error.code === 'string' &&
    typeof body.error.message === 'string'
  );
}

// ============================================================================
// HTTP Status Code Helpers
// ============================================================================

/**
 * Common HTTP status codes used in tests
 */
export const HttpStatus = {
  OK: 200,
  CREATED: 201,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  INTERNAL_SERVER_ERROR: 500,
} as const;

/**
 * Common error codes used in the application
 */
export const ErrorCodes = {
  BAD_REQUEST: 'BAD_REQUEST',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  ACCESS_DENIED: 'ACCESS_DENIED',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  INTERNAL_SERVER_ERROR: 'INTERNAL_SERVER_ERROR',
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_TOKEN: 'INVALID_TOKEN',
  CSRF_VALIDATION_FAILED: 'CSRF_VALIDATION_FAILED',
  PATIENT_NOT_FOUND: 'PATIENT_NOT_FOUND',
  CONSENT_REQUIRED: 'CONSENT_REQUIRED',
} as const;

// ============================================================================
// Test Data Builders
// ============================================================================

/**
 * Builds a query string from an object
 * 
 * @param params - Key-value pairs to convert to query string
 * @returns Query string (with leading ?)
 */
export function buildQueryString(params: Record<string, string | number | boolean | undefined>): string {
  const query = Object.entries(params)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');
  
  return query ? `?${query}` : '';
}

/**
 * Waits for a specified amount of time
 * 
 * @param ms - Milliseconds to wait
 * @returns Promise that resolves after the delay
 */
export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Retries an async operation until it succeeds or reaches max attempts
 * 
 * @param operation - The async operation to retry
 * @param maxAttempts - Maximum number of retry attempts
 * @param delayMs - Delay between retries in milliseconds
 * @returns The result of the operation
 */
export async function retry<T>(
  operation: () => Promise<T>,
  maxAttempts: number = 3,
  delayMs: number = 100
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts) {
        await wait(delayMs);
      }
    }
  }
  
  throw lastError!;
}

// ============================================================================
// Type Exports
// ============================================================================

/**
 * Type for mock express response with utility methods
 */
export interface MockResponse extends Response {
  _getStatusCode(): number;
  _getJSONData(): any;
  _getCookies(): Record<string, { value: string; options: MockCookieOptions }>;
  _isResponseSent(): boolean;
}
