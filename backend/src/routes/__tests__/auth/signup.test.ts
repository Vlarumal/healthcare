import request from 'supertest';
import jwt from 'jsonwebtoken';
import { AppDataSource } from '../../../../src/data-source';
import { Role } from '../../../types/auth';
import { createTestApp } from '../../../test-utils/appFactory';
import { mockRegularPatient } from '../../../test-utils/mockData';
import { resetMockServices } from '../../../test-utils/mockServices';
import { ValidationError } from '../../../errors/validationError';
import { setPasswordServiceInstance } from '../../authRoutes';

// Mock bcrypt for password hashing tests
jest.mock('bcrypt');

// Mock data-source
jest.mock('../../../../src/data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));

// Mock tempPasswordUtils
jest.mock('../../../utils/tempPasswordUtils');

// Mock auth middleware
jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn((_req, _res, next) => next()),
  authorizeRole: jest.fn((_roles: any) => (_req: any, _res: any, next: any) => next()),
}));

// Mock CSRF middleware
jest.mock('../../../middlewares/csrfMiddleware', () => ({
  doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
  generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  createCsrfMiddleware: jest.fn().mockReturnValue({
    doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
    generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  }),
}));

// Mock PasswordService - using same pattern as original file
jest.mock('../../../services/passwordService', () => {
  const actual = jest.requireActual('../../../services/passwordService');
  return {
    PasswordService: jest.fn().mockImplementation(() => {
      return {
        ...actual.PasswordService.prototype,
        validatePassword: jest.fn().mockImplementation((_password) => {
          return; // Don't throw by default - allows validation to pass
        }),
        hashPassword: jest.fn().mockImplementation((password) =>
          Promise.resolve(`hashed_${password}`)
        ),
      };
    }),
  };
});

// Token service mock
jest.mock('../../../services/tokenService', () => ({
  generateTokens: jest.fn().mockReturnValue({
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
  }),
  verifyRefreshToken: jest.fn(),
  rotateRefreshToken: jest.fn(),
  storeRefreshToken: jest.fn(),
  revokeToken: jest.fn(),
  revokeAllTokensForUser: jest.fn(),
  generateFingerprint: jest.fn().mockReturnValue('mock-fingerprint-hash'),
}));

// Import tokenService after mocking for spies
import * as tokenService from '../../../services/tokenService';

describe('POST /signup', () => {
  let app: any;

  // Mock tokens matching the original file format
  const mockAccessToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const mockRefreshToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MTA0ODQ4MDB9.4tC1L-4Q1g6K5ZQ7wY8z9X0vR1a2B3c4D5e6F7g8H9i0J';

  beforeEach(() => {
    jest.clearAllMocks();
    resetMockServices();
    app = createTestApp();

    // Setup jwt.decode mock matching original file (lines 160-174)
    jest.spyOn(jwt, 'decode').mockImplementation((token: string) => {
      if (token === mockRefreshToken) {
        return {
          jti: 'mock-token-id',
          exp: Math.floor(Date.now() / 1000) + 60,
          sub: '1',
        };
      }
      if (token === mockAccessToken) {
        return {
          sub: 'user-id',
          exp: Math.floor(Date.now() / 1000) + 15 * 60,
        };
      }
      return null;
    });

    // Setup jwt.verify mock matching original file (lines 176-187)
    jest.spyOn(jwt, 'verify').mockImplementation((token: string) => {
      if (token === mockRefreshToken || token === mockAccessToken) {
        return {
          jti: 'mock-token-id',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      throw new Error('Invalid token');
    });
  });

  afterEach(() => {
    setPasswordServiceInstance(null);
  });

  it('should signup successfully with valid data', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockReturnValue(mockRegularPatient),
      save: jest.fn().mockResolvedValue(mockRegularPatient),
    });

    (tokenService.generateTokens as jest.Mock).mockReturnValue({
      accessToken: mockAccessToken,
      refreshToken: mockRefreshToken,
    });
    (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

    const response = await request(app).post('/api/auth/signup').send({
      firstName: 'John',
      lastName: 'Doe',
      email: mockRegularPatient.email, // Use mock patient's email to match response
      password: 'Password123!',
      dateOfBirth: '1990-01-01',
    });

    expect(response.status).toBe(201);
    // Use toMatchObject to allow for additional fields in response
    expect(response.body).toMatchObject({
      id: mockRegularPatient.id,
      firstName: 'John',
      lastName: 'Doe',
      email: mockRegularPatient.email,
      dateOfBirth: '1990-01-01',
      role: Role.PATIENT,
    });
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should return 400 if email already exists', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockRegularPatient),
    });

    const response = await request(app).post('/api/auth/signup').send({
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      password: 'Password123!',
      dateOfBirth: '1990-01-01',
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        code: 'VALIDATION_ERROR',
        message: 'Validation failed',
        details: {
          errors: [
            {
              field: 'email',
              message: 'Email is already registered',
            },
          ],
        },
      },
    });
  });

  describe('Password Strength Validation', () => {
    it('should reject signup with weak password (too short)', async () => {
      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'weak', // Less than 8 characters
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'Minimum 8 characters',
              },
            ],
          },
        },
      });
    });

    it('should reject signup with weak password (no uppercase)', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new ValidationError([
            {
              field: 'password',
              message: 'At least one uppercase letter',
            },
          ]);
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'weakpassword123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'At least one uppercase letter',
              },
            ],
          },
        },
      });
    });

    it('should reject signup with weak password (no lowercase)', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new ValidationError([
            {
              field: 'password',
              message: 'At least one lowercase letter',
            },
          ]);
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'WEAKPASSWORD123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'At least one lowercase letter',
              },
            ],
          },
        },
      });
    });

    it('should reject signup with weak password (no number)', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new ValidationError([
            { field: 'password', message: 'At least one number' },
          ]);
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'WeakPassword!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              { field: 'password', message: 'At least one number' },
            ],
          },
        },
      });
    });

    it('should reject signup with weak password (no special character)', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new ValidationError([
            {
              field: 'password',
              message: 'At least one special character',
            },
          ]);
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'WeakPassword123',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'At least one special character',
              },
            ],
          },
        },
      });
    });

    it('should reject signup with weak password (common pattern)', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new ValidationError([
            {
              field: 'password',
              message: 'Password strength too weak',
            },
          ]);
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'Password123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'Password strength too weak',
              },
            ],
          },
        },
      });
    });

    it('should handle unexpected errors during password validation', async () => {
      const mockPasswordService = {
        validatePassword: jest.fn().mockImplementation(() => {
          throw new Error('Unexpected error during password validation');
        }),
        hashPassword: jest.fn(),
      };
      setPasswordServiceInstance(mockPasswordService as any);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn(),
        save: jest.fn(),
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'AnyPassword123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(400);
      expect(response.body).toEqual({
        error: {
          status: 400,
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: {
            errors: [
              {
                field: 'password',
                message: 'Unexpected error during password validation',
              },
            ],
          },
        },
      });
    });

    it('should handle undefined refresh token error', async () => {
      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockReturnValue(mockRegularPatient),
        save: jest.fn().mockResolvedValue(mockRegularPatient),
      });

      (tokenService.generateTokens as jest.Mock).mockReturnValue({
        accessToken: mockAccessToken,
        refreshToken: undefined,
      });
      (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'Password123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(500);
    });

    it('should handle invalid refresh token error', async () => {
      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockReturnValue(mockRegularPatient),
        save: jest.fn().mockResolvedValue(mockRegularPatient),
      });

      (tokenService.generateTokens as jest.Mock).mockReturnValue({
        accessToken: mockAccessToken,
        refreshToken: 'invalid-refresh-token',
      });
      (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

      // Mock jwt.decode to return null (simulating invalid token)
      (jwt.decode as jest.Mock).mockReturnValue(null);

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'Password123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(500);
    });

    it('should handle refresh token without jti', async () => {
      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockReturnValue(mockRegularPatient),
        save: jest.fn().mockResolvedValue(mockRegularPatient),
      });

      (tokenService.generateTokens as jest.Mock).mockReturnValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
      (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

      // Mock jwt.decode to return payload without jti
      (jwt.decode as jest.Mock).mockReturnValue({
        exp: Math.floor(Date.now() / 1000) + 86400,
        sub: '1',
        // missing jti
      });

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'Password123!',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(500);
    });

    it('should accept signup with strong password', async () => {
      setPasswordServiceInstance(null);

      (AppDataSource.getRepository as jest.Mock).mockReturnValue({
        findOne: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockReturnValue({
          ...mockRegularPatient,
          password: 'hashed_strong_password',
        }),
        save: jest.fn().mockResolvedValue({
          ...mockRegularPatient,
          password: 'hashed_strong_password',
        }),
      });

      (tokenService.generateTokens as jest.Mock).mockReturnValue({
        accessToken: mockAccessToken,
        refreshToken: mockRefreshToken,
      });
      (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

      const response = await request(app)
        .post('/api/auth/signup')
        .send({
          firstName: 'John',
          lastName: 'Doe',
          email: 'john.doe@example.com',
          password: 'Str0ng!P@ssw0rd123',
          dateOfBirth: '1990-01-01',
        });

      expect(response.status).toBe(201);
    });
  });
});
