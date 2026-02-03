/**
 * Authentication Middleware - Invalid Token Tests
 * Tests for invalid token scenarios
 */

// Module-level mocks - MUST be at top before imports
jest.mock('jsonwebtoken', () => {
  const originalModule = jest.requireActual('jsonwebtoken');
  return {
    ...originalModule,
    verify: jest.fn(),
    decode: jest.fn(),
  };
});

jest.mock('../../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authenticateJWT } from '../../../middlewares/authMiddleware';

describe('authenticateJWT - Invalid Token Scenarios', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
      cookies: {},
      ip: '127.0.0.1',
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    mockNext = jest.fn();

    (jwt.verify as jest.Mock).mockClear();
    (jwt.decode as jest.Mock).mockClear();
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next when token is malformed', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid.token.format',
    };
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.JsonWebTokenError('jwt malformed');
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Malformed token structure');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN_ALG code to next when token algorithm is wrong', async () => {
    mockRequest.headers = {
      authorization: 'Bearer wrong-algorithm-token',
    };
    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'none' },
      payload: {},
    }));
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.JsonWebTokenError('invalid algorithm');
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Unsupported token algorithm');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN_ALG code to next when token has invalid algorithm during verification', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid-algorithm-token',
    };
    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: {},
    }));
    (jwt.verify as jest.Mock).mockImplementation(
      (_token, _secret, _options, callback) => {
        callback(
          new jwt.JsonWebTokenError('invalid algorithm'),
          null
        );
      }
    );

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Unsupported token algorithm');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next when token is expired', async () => {
    mockRequest.headers = { authorization: 'Bearer expired-token' };
    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: {},
    }));
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.TokenExpiredError('jwt expired', new Date());
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Token expired');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next when token audience is invalid', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid-audience-token',
    };
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.JsonWebTokenError(
        'jwt audience invalid. expected: healthcare-audience'
      );
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Malformed token structure');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next when token issuer is invalid', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid-issuer-token',
    };
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.JsonWebTokenError(
        'jwt issuer invalid. expected: healthcare-system'
      );
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Malformed token structure');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next for generic JsonWebTokenError that does not match specific conditions', async () => {
    mockRequest.headers = { authorization: 'Bearer invalid-token' };
    (jwt.verify as jest.Mock).mockImplementation(() => {
      throw new jwt.JsonWebTokenError('Generic token error');
    });

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Malformed token structure');
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});

describe('authenticateJWT - JWT Verification Error Handling', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: { authorization: 'Bearer valid-token' },
      cookies: {},
      ip: '127.0.0.1',
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };

    mockNext = jest.fn();

    (jwt.verify as jest.Mock).mockClear();
    (jwt.decode as jest.Mock).mockClear();
  });

  it('should pass InternalServerError with AUTH_ERROR code to next when JWT verification fails', async () => {
    const logger = require('../../../utils/logger');
    const loggerErrorSpy = jest.spyOn(logger, 'error').mockImplementation();

    const mockError = new Error('JWT verification failed');
    (jwt.verify as jest.Mock).mockImplementation(
      (_token, _secret, _options, callback) => {
        callback(mockError, null);
      }
    );

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(loggerErrorSpy).toHaveBeenCalledWith(
      'JWT verification error:',
      mockError.message
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Authentication system failure');
    expect((error as any).statusCode).toBe(500);

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();

    loggerErrorSpy.mockRestore();
  });
});
