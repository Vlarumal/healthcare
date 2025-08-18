import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Patient } from '../../entities/Patient';
import crypto from 'crypto';
import logger from '../../utils/logger';

jest.mock('../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));

jest.mock('jsonwebtoken', () => {
  const originalModule = jest.requireActual('jsonwebtoken');
  return {
    ...originalModule,
    verify: jest.fn(),
    decode: jest.fn(),
  };
});
jest.mock('crypto');

import { AppDataSource } from '../../data-source';
import { authenticateJWT, authorizeRole } from '../authMiddleware';

const mockPatientRepo = {
  findOneBy: jest.fn(),
  findOne: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === Patient) return mockPatientRepo;
    return null;
  }
);

describe('authMiddleware', () => {
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
      headers: {},
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

  describe('Missing Token Scenarios', () => {
    it('should pass UnauthorizedError with MISSING_TOKEN code to next when no authorization header or cookie is present', async () => {
      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Authorization token required');
      expect(error.statusCode).toBe(401);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should pass UnauthorizedError with MISSING_TOKEN code to next when authorization header is present but empty', async () => {
      mockRequest.headers = { authorization: '' };

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Authorization token required');
      expect(error.statusCode).toBe(401);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should pass UnauthorizedError with MISSING_TOKEN code to next when cookie is present but empty', async () => {
      mockRequest.cookies = { accessToken: '' };

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Authorization token required');
      expect(error.statusCode).toBe(401);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('Invalid Token Scenarios', () => {
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
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
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('JWT Verification Error Handling', () => {
    it('should pass InternalServerError with AUTH_ERROR code to next when JWT verification fails', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };

      const loggerErrorSpy = jest
        .spyOn(logger, 'error')
        .mockImplementation();

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
      expect(error.statusCode).toBe(500);

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();

      loggerErrorSpy.mockRestore();
    });
  });

  describe('Token Binding Validation', () => {
    beforeEach(() => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockReturnValue(validPayload);
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });
    });

    it('should pass ForbiddenError with INVALID_TOKEN_BINDING code to next when token fingerprint validation requires current fingerprint in production', async () => {
      process.env.NODE_ENV = 'production';
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: undefined,
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest
              .fn()
              .mockReturnValue('different-fingerprint'),
          };
        }
      );

      const payloadWithFingerprint = {
        ...validPayload,
        fingerprint: 'some-fingerprint',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithFingerprint);
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Token binding validation failed');
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    }, 10000);

    it('should pass validation in test environment when token has fingerprint but current fingerprint is missing', async () => {
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: undefined,
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('valid-fingerprint'),
          };
        }
      );

      const payloadWithFingerprint = {
        ...validPayload,
        fingerprint: 'valid-fingerprint',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithFingerprint);
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should pass ForbiddenError with INVALID_TOKEN_BINDING code to next when token fingerprint does not match current fingerprint', async () => {
      process.env.NODE_ENV = 'production';
      mockRequest.headers = {
        authorization: 'Bearer valid-token',
        'user-agent': 'different-user-agent',
      };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: '192.168.1.1',
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      const payloadWithFingerprint = {
        ...validPayload,
        fingerprint: 'valid-fingerprint',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithFingerprint);
        }
      );

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_BINDING_SECRET) {
            return {
              update: jest.fn().mockImplementation((data) => {
                const userAgent =
                  mockRequest.headers?.['user-agent'] || '';
                const ip = mockRequest.ip || '';
                if (data === `${userAgent}${ip}`) {
                  return {
                    digest: jest
                      .fn()
                      .mockReturnValue('different-fingerprint'),
                  };
                }
                return {
                  digest: jest
                    .fn()
                    .mockReturnValue('different-fingerprint'),
                };
              }),
              digest: jest
                .fn()
                .mockReturnValue('different-fingerprint'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('default-hash'),
          };
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Token binding validation failed');
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    }, 10000);
  });

  describe('Token Version Validation', () => {
    it('should pass ForbiddenError with TOKEN_REVOKED code to next when token version hash is invalid', async () => {
      process.env.NODE_ENV = 'production';
      mockRequest.headers = {
        authorization: 'Bearer invalid-version-token',
        'user-agent': 'test-agent',
      };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: '127.0.0.1',
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      const payloadWithInvalidVersion = {
        ...validPayload,
        tokenVersionHash: 'invalid-hash',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithInvalidVersion);
        }
      );

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_BINDING_SECRET) {
            return {
              update: jest.fn().mockImplementation((data) => {
                const userAgent =
                  mockRequest.headers?.['user-agent'] || '';
                const ip = mockRequest.ip || '';
                if (data === `${userAgent}${ip}`) {
                  return {
                    digest: jest
                      .fn()
                      .mockReturnValue('valid-fingerprint'),
                  };
                }
                return {
                  digest: jest
                    .fn()
                    .mockReturnValue('different-fingerprint'),
                };
              }),
              digest: jest.fn().mockReturnValue('valid-fingerprint'),
            };
          }
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('different-hash'),
          };
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Session invalidated');
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('Password Version Validation', () => {
    beforeEach(() => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, validPayload);
        }
      );
    });

    it('should pass ForbiddenError with CREDENTIALS_CHANGED code to next when user password version does not match token password version', async () => {
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 2,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.message).toBe('Please reauthenticate');
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    }, 10000);

    it('should call next when user password version matches token password version', async () => {
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    }, 10000);
  });

  describe('Database Connection Errors', () => {
    it('should pass InternalServerError with AUTH_ERROR code to next when database connection fails during user lookup', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
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
    }, 10000);

    it('should pass NotFoundError with USER_NOT_FOUND code to next when user is not found in database', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
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
    }, 10000);
  });

  describe('Invalid User ID in Token', () => {
    it('should pass ForbiddenError with INVALID_TOKEN code to next when user ID in token is not a valid number', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      const payloadWithInvalidUserId = {
        ...validPayload,
        sub: 'invalid-user-id',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
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
      expect(error.message).toBe(
        'Invalid user ID in token: invalid-user-id'
      );
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('Database Repository Access Errors', () => {
    it('should pass ServiceUnavailableError with SERVICE_UNAVAILABLE code to next when database repository access fails', async () => {
      (
        AppDataSource.getRepository as jest.Mock
      ).mockImplementationOnce(() => {
        throw new Error('Database connection pool exhausted');
      });

      const loggerErrorSpy = jest
        .spyOn(logger, 'error')
        .mockImplementation();

      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
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

  describe('Security Report Edge Cases', () => {
    it('should handle tokens without fingerprint in production environment', async () => {
      process.env.NODE_ENV = 'production';
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: '127.0.0.1',
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      const payloadWithoutFingerprint = {
        ...validPayload,
        fingerprint: undefined,
        iss: 'healthcare-system',
        aud: 'healthcare-audience',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithoutFingerprint);
        }
      );

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('valid-fingerprint'),
          };
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });

    it('should handle tokens with empty fingerprint string', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      const payloadWithEmptyFingerprint = {
        ...validPayload,
        fingerprint: '',
        iss: 'healthcare-system',
        aud: 'healthcare-audience',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithEmptyFingerprint);
        }
      );

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('valid-fingerprint'),
          };
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('Environment Differences', () => {
    it('should skip fingerprint validation in test environment', async () => {
      process.env.NODE_ENV = 'test';
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: undefined,
      };

      const payloadWithFingerprint = {
        ...validPayload,
        fingerprint: 'some-fingerprint',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithFingerprint);
        }
      );
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockResponse.status).not.toHaveBeenCalled();
    }, 10000);

    it('should pass ForbiddenError with INVALID_TOKEN_BINDING code to next when enforcing fingerprint validation in production environment', async () => {
      process.env.NODE_ENV = 'production';
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      mockRequest = {
        headers: mockRequest.headers,
        cookies: mockRequest.cookies,
        ip: undefined,
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      const payloadWithFingerprint = {
        ...validPayload,
        fingerprint: 'some-fingerprint',
      };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, payloadWithFingerprint);
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);

      expect(error.message).toBe('Token binding validation failed');
      expect(error.statusCode).toBe(403);
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });

  describe('Environment Variable Validation', () => {
    it('should pass InternalServerError with SERVER_ERROR code to next when TOKEN_BINDING_SECRET environment variable is not set', async () => {
      const originalTokenBindingSecret =
        process.env.TOKEN_BINDING_SECRET;
      delete process.env.TOKEN_BINDING_SECRET;

      const loggerErrorSpy = jest
        .spyOn(logger, 'error')
        .mockImplementation();

      mockRequest.headers = { authorization: 'Bearer valid-token' };

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'TOKEN_BINDING_SECRET environment variable is not set'
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.code).toBe('INTERNAL_SERVER_ERROR');
      expect(error.message).toBe('Internal server error');
      expect(error.statusCode).toBe(500);

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();

      process.env.TOKEN_BINDING_SECRET = originalTokenBindingSecret;

      loggerErrorSpy.mockRestore();
    });

    it('should pass InternalServerError with SERVER_ERROR code to next when TOKEN_VERSION environment variable is not set', async () => {
      const originalTokenVersion = process.env.TOKEN_VERSION;
      delete process.env.TOKEN_VERSION;

      const loggerErrorSpy = jest
        .spyOn(logger, 'error')
        .mockImplementation();

      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, validPayload);
        }
      );
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(loggerErrorSpy).toHaveBeenCalledWith(
        'TOKEN_VERSION environment variable is not set'
      );

      expect(mockNext).toHaveBeenCalled();
      const error = (mockNext as jest.Mock).mock.calls[0][0];
      expect(error).toBeInstanceOf(Error);
      expect(error.code).toBe('INTERNAL_SERVER_ERROR');
      expect(error.message).toBe('Internal server error');
      expect(error.statusCode).toBe(500);

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();

      process.env.TOKEN_VERSION = originalTokenVersion;

      loggerErrorSpy.mockRestore();
    });
  });

  describe('Successful Authentication', () => {
    it('should call next and attach user to request when authentication is successful', async () => {
      mockRequest.headers = { authorization: 'Bearer valid-token' };
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, validPayload);
        }
      );
      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toEqual({
        id: 1,
        role: 'patient',
      });
      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    }, 10000);

    it('should handle token from cookie when authorization header is not present', async () => {
      mockRequest.headers = {};
      mockRequest.cookies = {
        accessToken: 'valid-token-from-cookie',
      };

      (jwt.decode as jest.Mock).mockImplementation(() => ({
        header: { alg: 'RS256' },
        payload: validPayload,
      }));

      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _secret, _options, callback) => {
          callback(null, validPayload);
        }
      );

      (crypto.createHmac as jest.Mock).mockImplementation(
        (_algorithm, key) => {
          if (key === process.env.TOKEN_VERSION) {
            return {
              update: jest.fn().mockReturnThis(),
              digest: jest.fn().mockReturnValue('expected-hash'),
            };
          }
          return {
            update: jest.fn().mockReturnThis(),
            digest: jest.fn().mockReturnValue('valid-fingerprint'),
          };
        }
      );

      mockPatientRepo.findOne.mockResolvedValue({
        id: 1,
        role: 'patient',
        passwordVersion: 1,
      });

      await authenticateJWT(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();
      expect(mockRequest.user).toEqual({
        id: 1,
        role: 'patient',
      });
    });
  });

  describe('authorizeRole', () => {
    let mockRequest: Partial<Request>;
    let mockResponse: Partial<Response>;
    let mockNext: NextFunction;

    beforeEach(() => {
      mockRequest = {};
      mockResponse = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
    });

    it('should call next() when user has required role', () => {
      mockRequest.user = {
        id: 1,
        role: 'admin',
      };

      const roleMiddleware = authorizeRole(['admin', 'clinician']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should return 403 when user does not have required role', () => {
      mockRequest.user = {
        id: 1,
        role: 'patient',
      };

      const roleMiddleware = authorizeRole(['admin', 'clinician']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when user has no role defined', () => {
      mockRequest.user = {
        id: 1,
        role: undefined as any,
      };

      const roleMiddleware = authorizeRole(['admin', 'clinician']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });

      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should return 403 when no user object is attached to request', () => {
      mockRequest.user = undefined;

      const roleMiddleware = authorizeRole(['admin', 'clinician']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockResponse.status).toHaveBeenCalledWith(403);
      expect(mockResponse.json).toHaveBeenCalledWith({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });

      expect(mockNext).not.toHaveBeenCalled();
    });
    it('should call next() when user has clinician role', () => {
      mockRequest.user = {
        id: 1,
        role: 'clinician',
      };

      const roleMiddleware = authorizeRole(['admin', 'clinician']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });

    it('should call next() when user has staff role', () => {
      mockRequest.user = {
        id: 1,
        role: 'staff',
      };

      const roleMiddleware = authorizeRole(['admin', 'staff']);

      roleMiddleware(
        mockRequest as Request,
        mockResponse as Response,
        mockNext
      );

      expect(mockNext).toHaveBeenCalled();

      expect(mockResponse.status).not.toHaveBeenCalled();
      expect(mockResponse.json).not.toHaveBeenCalled();
    });
  });
});
