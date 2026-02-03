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

describe('authenticateJWT - Token Binding Validation', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
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

  it('should pass ForbiddenError with INVALID_TOKEN_BINDING code to next when token fingerprint validation requires current fingerprint in production', async () => {
    process.env.NODE_ENV = 'production';
    mockRequest = {
      headers: { authorization: 'Bearer valid-token' },
      cookies: {},
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
          digest: jest.fn().mockReturnValue('different-fingerprint'),
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
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });

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
    mockRequest = {
      headers: {
        authorization: 'Bearer valid-token',
        'user-agent': 'different-user-agent',
      },
      cookies: {},
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
                  digest: jest.fn().mockReturnValue('different-fingerprint'),
                };
              }
              return {
                digest: jest.fn().mockReturnValue('different-fingerprint'),
              };
            }),
            digest: jest.fn().mockReturnValue('different-fingerprint'),
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
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});

describe('Security Report Edge Cases', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

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

  it('should handle tokens without fingerprint in production environment', async () => {
    process.env.NODE_ENV = 'production';
    mockRequest = {
      headers: { authorization: 'Bearer valid-token' },
      cookies: {},
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
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;
  let validPayload: any;

  beforeEach(() => {
    mockRequest = {
      headers: { authorization: 'Bearer valid-token' },
      cookies: {},
      ip: undefined,
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

  it('should skip fingerprint validation in test environment', async () => {
    process.env.NODE_ENV = 'test';

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
  });

  it('should pass ForbiddenError with INVALID_TOKEN_BINDING code to next when enforcing fingerprint validation in production environment', async () => {
    process.env.NODE_ENV = 'production';

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
    expect((error as any).statusCode).toBe(403);
    expect(mockResponse.status).not.toHaveBeenCalled();
    expect(mockResponse.json).not.toHaveBeenCalled();
  });
});
