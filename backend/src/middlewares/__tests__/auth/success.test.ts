import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Patient } from '../../../entities/Patient';
import crypto from 'crypto';
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

const mockPatientRepo = {
  findOne: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity === Patient) return mockPatientRepo;
    return null;
  }
);

describe('authenticateJWT - Successful Authentication', () => {
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

  it('should call next and attach user to request when authentication is successful', async () => {
    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));

    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
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
  });

  it('should handle token from cookie when authorization header is not present', async () => {
    mockRequest = {
      headers: {},
      cookies: { accessToken: 'valid-token-from-cookie' },
      ip: '127.0.0.1',
    };

    (jwt.decode as jest.Mock).mockImplementation(() => ({
      header: { alg: 'RS256' },
      payload: validPayload,
    }));

    (jwt.verify as jest.Mock).mockImplementation(
      (_token: string, _secret: string, _options: any, callback: Function) => {
        callback(null, validPayload);
      }
    );

    (crypto.createHmac as jest.Mock).mockImplementation(
      (_algorithm: string, key: string) => {
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
