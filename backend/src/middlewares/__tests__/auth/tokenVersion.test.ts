import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { authenticateJWT } from '../../../middlewares/authMiddleware';
import { AppDataSource } from '../../../data-source';
import { Patient } from '../../../entities/Patient';

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

describe('authenticateJWT - Token Version Validation', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    process.env.NODE_ENV = 'production';
    process.env.TOKEN_VERSION = 'test-version';
    process.env.TOKEN_BINDING_SECRET = 'test-binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

    mockRequest = {
      headers: {
        authorization: 'Bearer invalid-version-token',
        'user-agent': 'test-agent',
      },
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

  it('should pass ForbiddenError with TOKEN_REVOKED code to next when token version hash is invalid', async () => {
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
                  digest: jest.fn().mockReturnValue('valid-fingerprint'),
                };
              }
              return {
                digest: jest.fn().mockReturnValue('different-fingerprint'),
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
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});
