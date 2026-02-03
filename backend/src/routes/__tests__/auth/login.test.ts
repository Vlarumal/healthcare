import request from 'supertest';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { AppDataSource } from '../../../../src/data-source';
import { Role } from '../../../types/auth';
import { UnauthorizedError } from '../../../errors/httpErrors';
import { createTestApp } from '../../../test-utils/appFactory';
import { mockLoginPatient } from '../../../test-utils/mockData';
import { resetMockServices, mockTokenService } from '../../../test-utils/mockServices';

// Mock services - use the same pattern as signup.test.ts
jest.mock('../../../services/tokenService', () => require('../../../test-utils/mockServices').mockTokenService);
jest.mock('bcrypt');
jest.mock('../../../../src/data-source');
jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn((_req: any, _res: any, next: any) => next()),
  authorizeRole: jest.fn((_roles: any) => (_req: any, _res: any, next: any) => next()),
}));
jest.mock('../../../middlewares/csrfMiddleware', () => ({
  doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
  generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  createCsrfMiddleware: jest.fn().mockReturnValue({
    doubleCsrfProtection: jest.fn((_req, _res, next) => next()),
    generateCsrfToken: jest.fn().mockReturnValue('mock-csrf-token'),
  }),
}));
jest.mock('../../../utils/errorLogger', () => ({
  logError: jest.fn(),
  logWarning: jest.fn(),
}));

describe('POST /login', () => {
  let app: any;
  let csrfTokenMock = 'mock-csrf-token';

  const mockAccessToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const mockRefreshToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MTA0ODQ4MDB9.4tC1L-4Q1g6K5ZQ7wY8z9X0vR1a2B3c4D5e6F7g8H9i0J';

  const mockTokens = {
    accessToken: mockAccessToken,
    refreshToken: mockRefreshToken,
  };

  beforeEach(() => {
    resetMockServices();
    csrfTokenMock = 'mock-csrf-token';
    app = createTestApp((testApp) => {
      // Add custom CSRF token endpoint for concurrent login tests
      testApp.get('/auth/csrf-token', (_req, res) => {
        res.json({ csrfToken: csrfTokenMock });
      });
    });

    jest.spyOn(jwt, 'decode').mockImplementation((token: string) => {
      if (token === mockTokens.refreshToken) {
        return {
          jti: 'mock-token-id',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      if (token === mockTokens.accessToken) {
        return {
          sub: 'user-id',
          exp: Math.floor(Date.now() / 1000) + 15 * 60,
        };
      }
      return null;
    });

    jest.spyOn(jwt, 'verify').mockImplementation((token: string) => {
      if (
        token === mockTokens.refreshToken ||
        token === mockTokens.accessToken
      ) {
        return {
          jti: 'mock-token-id',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      throw new Error('Invalid token');
    });
  });

  it('should login successfully with valid credentials', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (mockTokenService.generateTokens as jest.Mock).mockReturnValue(mockTokens);
    (mockTokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);
    (mockTokenService.revokeAllTokensForUser as jest.Mock).mockResolvedValue(1);

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'john.doe@example.com',
        password: 'Password123!',
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      id: 1,
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      role: Role.PATIENT,
    });
    expect(response.headers['set-cookie']).toBeDefined();
    expect(bcrypt.compare).toHaveBeenCalledWith(
      'Password123!',
      'hashed_password'
    );
  });

  it('should return 401 for invalid credentials', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });
    (bcrypt.compare as jest.Mock).mockResolvedValue(false);

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'john.doe@example.com',
        password: 'wrongpassword',
      });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: 'Invalid credentials',
    });
  });

  it('should return 401 for non-existent user', async () => {
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(null),
    });

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'nonexistent@example.com',
        password: 'password',
      });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: 'Invalid credentials',
    });
  });

  it('should login with temporary password and require reset', async () => {
    const patientWithTempPassword = {
      ...mockLoginPatient,
      temporaryPassword: 'hashed_temp_password',
    };
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(patientWithTempPassword),
    });
    (bcrypt.compare as jest.Mock).mockImplementation(
      (_password, hash) => {
        if (hash === 'hashed_temp_password') {
          return Promise.resolve(true);
        }
        return Promise.resolve(false);
      }
    );
    (mockTokenService.generateTokens as jest.Mock).mockReturnValue({
      accessToken: 'temp-access-token',
      refreshToken: null,
    });

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'john.doe@example.com',
        password: 'temp123!',
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ resetRequired: true });
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should login with regular password but require reset', async () => {
    const patientWithResetRequired = {
      ...mockLoginPatient,
      resetRequired: true,
    };
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(patientWithResetRequired),
    });
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (mockTokenService.generateTokens as jest.Mock).mockReturnValue({
      accessToken: 'temp-access-token',
      refreshToken: null,
    });

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'john.doe@example.com',
        password: 'Password123!',
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ resetRequired: true });
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should log token revocation failures but continue with login', async () => {
    const ErrorLogger = require('../../../utils/errorLogger');
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (mockTokenService.generateTokens as jest.Mock).mockReturnValue(mockTokens);
    (mockTokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);
    (mockTokenService.revokeAllTokensForUser as jest.Mock).mockRejectedValue(
      new Error('Database connection failed')
    );

    const logErrorSpy = jest.spyOn(ErrorLogger, 'logError').mockImplementation();
    const logWarningSpy = jest.spyOn(ErrorLogger, 'logWarning').mockImplementation();

    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'john.doe@example.com',
        password: 'Password123!',
      });

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      id: 1,
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      role: Role.PATIENT,
    });
    expect(response.headers['set-cookie']).toBeDefined();

    expect(logErrorSpy).toHaveBeenCalledWith(
      new Error('Database connection failed'),
      { userId: 1, message: 'Token revocation failed' }
    );
    expect(logWarningSpy).toHaveBeenCalledWith(
      'Proceeding with login despite token revocation failure',
      { userId: 1 }
    );

    logErrorSpy.mockRestore();
    logWarningSpy.mockRestore();
  });
});

describe('POST /login - Concurrent Login Attempts', () => {
  let app: any;
  let tokenRepoMock: any;
  let storedTokens: any[] = [];
  let csrfTokenMock = 'mock-csrf-token';

  beforeEach(() => {
    resetMockServices();
    csrfTokenMock = 'mock-csrf-token';
    app = createTestApp((testApp) => {
      // Add custom CSRF token endpoint for concurrent login tests
      testApp.get('/auth/csrf-token', (_req, res) => {
        res.json({ csrfToken: csrfTokenMock });
      });
    });

    tokenRepoMock = {
      findOne: jest.fn().mockImplementation((options) => {
        return Promise.resolve(
          storedTokens.find((t) => t.token === options.where.token)
        );
      }),
      create: jest.fn().mockImplementation((tokenData) => {
        const token = { ...tokenData, id: storedTokens.length + 1 };
        storedTokens.push(token);
        return token;
      }),
      save: jest.fn().mockImplementation((token) => {
        const existing = storedTokens.findIndex((t) => t.id === token.id);
        if (existing >= 0) {
          storedTokens[existing] = token;
        } else {
          token.id = storedTokens.length + 1;
          storedTokens.push(token);
        }
        return Promise.resolve(token);
      }),
      update: jest
        .fn()
        .mockImplementation((criteria, _updates) => {
          const tokens = storedTokens.filter(
            (t) => t.patient?.id === criteria.patient?.id && !t.revoked
          );
          tokens.forEach((token) => {
            token.revoked = true;
          });
          return Promise.resolve({ affected: tokens.length });
        }),
    };

    // Mock patient for concurrent login tests - use 'test@example.com' to match signup
    const mockPatientForConcurrentLogin = {
      id: 1,
      firstName: 'Test',
      lastName: 'User',
      email: 'test@example.com',
      password: 'hashed_password',
      role: Role.PATIENT as any,
      passwordVersion: 1,
      temporaryPassword: null,
      resetRequired: false,
      toJSON: function() {
        return {
          id: this.id,
          firstName: this.firstName,
          lastName: this.lastName,
          email: this.email,
          role: this.role,
        };
      },
    };

    (AppDataSource.getRepository as jest.Mock).mockImplementation((entity: any) => {
      if (entity?.name === 'Token') return tokenRepoMock;
      return {
        findOne: jest.fn().mockResolvedValue(mockPatientForConcurrentLogin),
        save: jest.fn(),
      };
    });

    (mockTokenService.generateTokens as jest.Mock)
      .mockImplementationOnce(() => ({
        accessToken: 'access-token-1',
        refreshToken:
          'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTEiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-1',
      }))
      .mockImplementationOnce(() => ({
        accessToken: 'access-token-2',
        refreshToken:
          'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTIiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-2',
      }))
      .mockImplementationOnce(() => ({
        accessToken: 'access-token-3',
        refreshToken:
          'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTMiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-3',
      }));

    (mockTokenService.storeRefreshToken as jest.Mock).mockImplementation(
      (userId, tokenId, expiresAt) => {
        const token = {
          id: storedTokens.length + 1,
          token: tokenId,
          patient: { id: userId },
          expiresAt: new Date(expiresAt),
          revoked: false,
        };
        storedTokens.push(token);
        return Promise.resolve();
      }
    );

    (bcrypt.compare as jest.Mock).mockResolvedValue(true);

    (mockTokenService.revokeAllTokensForUser as jest.Mock).mockImplementation(
      (userId) => {
        const tokens = storedTokens.filter(
          (t) => t.patient?.id === userId && !t.revoked
        );
        tokens.forEach((token) => {
          token.revoked = true;
        });
        return Promise.resolve(tokens.length);
      }
    );

    (mockTokenService.verifyRefreshToken as jest.Mock).mockImplementation(
      (token) => {
        const storedToken = storedTokens.find((t) => t.token === token);

        if (!storedToken) {
          throw new UnauthorizedError('Invalid refresh token');
        }

        if (storedToken.revoked) {
          throw new UnauthorizedError('Refresh token revoked');
        }

        return Promise.resolve({
          jti: storedToken.token,
          userId: storedToken.patient.id,
          tokenVersion: process.env.TOKEN_VERSION,
          exp: Math.floor(storedToken.expiresAt.getTime() / 1000),
        });
      }
    );

    jest.spyOn(jwt, 'decode').mockImplementation((token: string) => {
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTEiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-1'
      ) {
        return {
          jti: 'mock-token-id-1',
          exp: Math.floor(Date.now() / 1000) + 60, // 60 seconds expiration
        };
      }
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTIiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-2'
      ) {
        return {
          jti: 'mock-token-id-2',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTMiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-3'
      ) {
        return {
          jti: 'mock-token-id-3',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      return null;
    });

    // Mock jwt.verify to prevent signature validation errors
    jest.spyOn(jwt, 'verify').mockImplementation((token: string) => {
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTEiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-1'
      ) {
        return {
          jti: 'mock-token-id-1',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTIiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-2'
      ) {
        return {
          jti: 'mock-token-id-2',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      if (
        token ===
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJtb2NrLXRva2VuLWlkLTMiLCJleHAiOjE3MTA0ODQ4MDB9.mock-signature-3'
      ) {
        return {
          jti: 'mock-token-id-3',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      throw new Error('Invalid token');
    });
  });

  afterEach(() => {
    storedTokens = [];
  });

  it('should allow multiple concurrent login attempts for the same user', async () => {
    const csrfResponse = await request(app).get('/auth/csrf-token');
    const csrfToken = csrfResponse.body.csrfToken;

    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });

    const requests = [
      request(app)
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'john.doe@example.com',
          password: 'Password123!',
        }),
      request(app)
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'john.doe@example.com',
          password: 'Password123!',
        }),
      request(app)
        .post('/api/auth/login')
        .set('X-CSRF-Token', csrfToken)
        .send({
          email: 'john.doe@example.com',
          password: 'Password123!',
        }),
    ];

    const responses = await Promise.all(requests);

    responses.forEach((response) => {
      expect(response.status).toBe(200);
      expect(response.body).toEqual({
        id: 1,
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        role: Role.PATIENT,
      });
      expect(response.headers['set-cookie']).toBeDefined();
    });

    expect(mockTokenService.generateTokens).toHaveBeenCalledTimes(3);
    expect(mockTokenService.storeRefreshToken).toHaveBeenCalledTimes(3);
    expect(mockTokenService.revokeAllTokensForUser).toHaveBeenCalledTimes(3);
  });

  it('should properly invalidate previous refresh tokens on new login', async () => {
    const csrfResponse = await request(app).get('/auth/csrf-token');
    const csrfToken = csrfResponse.body.csrfToken;

    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });

    const firstLoginResponse = await request(app)
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'john.doe@example.com',
        password: 'Password123!',
      });

    const secondLoginResponse = await request(app)
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'john.doe@example.com',
        password: 'Password123!',
      });

    expect(firstLoginResponse.status).toBe(200);
    expect(secondLoginResponse.status).toBe(200);

    expect(mockTokenService.storeRefreshToken).toHaveBeenCalledTimes(2);
    expect(mockTokenService.revokeAllTokensForUser).toHaveBeenCalledTimes(2);
  });

  it('should revoke previous tokens on new login', async () => {
    const csrfResponse = await request(app).get('/auth/csrf-token');
    const csrfToken = csrfResponse.body.csrfToken;

    await request(app)
      .post('/api/auth/signup')
      .set('x-csrf-token', 'mock-csrf-token')
      .send({
        email: 'test@example.com',
        password: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
        role: 'doctor',
        dateOfBirth: '1990-01-01',
      });

    const firstLogin = await request(app)
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'test@example.com',
        password: 'Password123!',
      });

    const setCookieHeader = firstLogin.headers['set-cookie'];
    const firstRefreshToken = Array.isArray(setCookieHeader)
      ? setCookieHeader
          .find((cookie: string) => cookie.startsWith('refreshToken='))
          ?.split(';')[0]
          ?.split('=')[1]
      : undefined;

    expect(firstLogin.status).toBe(200);
    expect(storedTokens.length).toBe(1);
    expect(firstRefreshToken).toBeDefined();

    const secondLogin = await request(app)
      .post('/api/auth/login')
      .set('X-CSRF-Token', csrfToken)
      .send({
        email: 'test@example.com',
        password: 'Password123!',
      });

    expect(secondLogin.status).toBe(200);
    expect(storedTokens.length).toBe(2);
    expect(storedTokens[0]?.revoked).toBe(true);

    const refreshResponse = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${firstRefreshToken}`]);

    expect(refreshResponse.status).toBe(401);
    expect(refreshResponse.body).toEqual({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Invalid refresh token',
        status: 401,
      },
    });
  });

  it('should handle concurrent logins correctly', async () => {
    await request(app)
      .post('/api/auth/signup')
      .set('x-csrf-token', 'mock-csrf-token')
      .send({
        email: 'test@example.com',
        password: 'Password123!',
        firstName: 'Test',
        lastName: 'User',
        role: 'doctor',
        dateOfBirth: '1990-01-01',
      });

    await request(app)
      .post('/api/auth/login')
      .send({
        email: 'test@example.com',
        password: 'Password123!',
      });

    const secondLogin = await request(app)
      .post('/api/auth/login')
      .set('x-csrf-token', 'mock-csrf-token')
      .send({
        email: 'test@example.com',
        password: 'Password123!',
      });
    expect(secondLogin.status).toBe(200);
    expect(storedTokens.filter((t) => t.revoked).length).toBe(1);

    const thirdLogin = await request(app)
      .post('/api/auth/login')
      .set('x-csrf-token', 'mock-csrf-token')
      .send({
        email: 'test@example.com',
        password: 'Password123!',
      });
    expect(thirdLogin.status).toBe(200);
    expect(storedTokens.filter((t) => t.revoked).length).toBe(2);
  });
});
