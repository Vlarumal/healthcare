import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Patient } from '../../../entities/Patient';
import crypto from 'crypto';
import logger from '../../../utils/logger';
import { authenticateJWT } from '../../../middlewares/authMiddleware';
import { AppDataSource } from '../../../data-source';

jest.mock('jsonwebtoken', () => {
  const originalModule = jest.requireActual('jsonwebtoken');
  return {
    ...originalModule,
    verify: jest.fn(),
    decode: jest.fn(),
  };
});

jest.mock('crypto');
jest.mock('../../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));
jest.mock('../../../utils/logger');

const mockPatientRepo = {
  findOne: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === Patient) return mockPatientRepo;
    return null;
  }
);

describe('authenticateJWT - JWT Verification Error Handling', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    jest.clearAllMocks();

    process.env.NODE_ENV = 'test';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

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

    validPayload = {
      sub: '1',
      role: 'patient',
      passwordVersion: 1,
      tokenVersionHash: 'expected-hash',
      fingerprint: 'valid-fingerprint',
      iss: 'healthcare-system',
      aud: 'healthcare-audience',
    };

    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));

    (crypto.createHmac as jest.Mock).mockImplementation(() => ({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('valid-fingerprint'),
    }));
  });

  afterEach(() => {
    process.env.NODE_ENV = 'test';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';
  });

  it('should pass InternalServerError with AUTH_ERROR code to next when JWT verification fails', async () => {
    const loggerErrorSpy = jest
      .spyOn(logger, 'error')
      .mockImplementation();

    const mockError = new Error('JWT verification failed');
    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
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
    expect(error.statusCode).toBe(500);

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();

    loggerErrorSpy.mockRestore();
  });
});

describe('authenticateJWT - Database Errors', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    jest.clearAllMocks();

    process.env.NODE_ENV = 'test';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

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

    validPayload = {
      sub: '1',
      role: 'patient',
      passwordVersion: 1,
      tokenVersionHash: 'expected-hash',
      fingerprint: 'valid-fingerprint',
      iss: 'healthcare-system',
      aud: 'healthcare-audience',
    };

    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));

    (crypto.createHmac as jest.Mock).mockImplementation(() => ({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('valid-fingerprint'),
    }));
  });

  it('should pass InternalServerError with AUTH_ERROR code to next when database connection fails', async () => {
    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
        callback(null, validPayload);
      }
    );

    mockPatientRepo.findOne.mockRejectedValue(
      new Error('Database connection failed')
    );

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('Authentication system failure');
    expect(error.statusCode).toBe(500);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

  it('should pass NotFoundError with USER_NOT_FOUND code to next when user is not found', async () => {
    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
        callback(null, validPayload);
      }
    );

    mockPatientRepo.findOne.mockResolvedValue(null);

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.message).toBe('User not found');
    expect(error.statusCode).toBe(404);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});

describe('authenticateJWT - Invalid User ID', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    jest.clearAllMocks();

    process.env.NODE_ENV = 'test';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

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

    validPayload = {
      sub: '1',
      role: 'patient',
      passwordVersion: 1,
      tokenVersionHash: 'expected-hash',
      fingerprint: 'valid-fingerprint',
      iss: 'healthcare-system',
      aud: 'healthcare-audience',
    };

    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));

    (crypto.createHmac as jest.Mock).mockImplementation(() => ({
      update: jest.fn().mockReturnThis(),
      digest: jest.fn().mockReturnValue('valid-fingerprint'),
    }));
  });

  it('should pass ForbiddenError with INVALID_TOKEN code to next when user ID in token is not a valid number', async () => {
    const payloadWithInvalidUserId = {
      ...validPayload,
      sub: 'invalid-user-id',
    };

    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
        callback(null, payloadWithInvalidUserId);
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
    expect(error.message).toBe('Invalid user ID in token: invalid-user-id');
    expect(error.statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});

describe('authenticateJWT - Database Repository Access Errors', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    jest.clearAllMocks();

    process.env.NODE_ENV = 'test';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

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

    validPayload = {
      sub: '1',
      role: 'patient',
      passwordVersion: 1,
      tokenVersionHash: 'expected-hash',
      fingerprint: 'valid-fingerprint',
      iss: 'healthcare-system',
      aud: 'healthcare-audience',
    };

    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));
  });

  it('should pass ServiceUnavailableError with SERVICE_UNAVAILABLE code to next when database repository access fails', async () => {
    (AppDataSource.getRepository as jest.Mock).mockImplementationOnce(() => {
      throw new Error('Database connection pool exhausted');
    });

    const loggerErrorSpy = jest
      .spyOn(logger, 'error')
      .mockImplementation();

    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
        callback(null, validPayload);
      }
    );

    await authenticateJWT(
      mockRequest as Request,
      mockResponse as Response,
      mockNext
    );

    expect(loggerErrorSpy).toHaveBeenCalledWith(
      'Database repository access failed:',
      new Error('Database connection pool exhausted')
    );

    expect(mockNext).toHaveBeenCalled();
    const error = (mockNext as jest.Mock).mock.calls[0][0];
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe('SERVICE_UNAVAILABLE');
    expect(error.message).toBe('Database service is initializing');
    expect(error.statusCode).toBe(503);

    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();

    loggerErrorSpy.mockRestore();
  });
});
