import request from 'supertest';
import jwt from 'jsonwebtoken';
import { AppDataSource } from '../../../data-source';
import { Role } from '../../../types/auth';
import { createTestApp } from '../../../test-utils/appFactory';
import { mockRegularPatient } from '../../../test-utils/mockData';

// Mock data-source
jest.mock('../../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));

// Mock services - all requires must be inside jest.mock() to be properly hoisted
jest.mock('../../../services/tokenService', () => ({
  generateTokens: jest.fn(),
  verifyRefreshToken: jest.fn(),
  rotateRefreshToken: jest.fn(),
  storeRefreshToken: jest.fn(),
  revokeToken: jest.fn(),
  revokeAllTokensForUser: jest.fn(),
  generateFingerprint: jest.fn().mockReturnValue('mock-fingerprint-hash'),
}));

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

// Mock jwt module to avoid actual JWT operations
jest.mock('jsonwebtoken', () => ({
  decode: jest.fn().mockReturnValue({
    jti: 'new-mock-jti-123',
    userId: 1,
    exp: Math.floor(Date.now() / 1000) + 3600,
  }),
  sign: jest.fn().mockReturnValue('mock-jwt-signature'),
  verify: jest.fn(),
}));

// Import tokenService after mocking for spies
import * as tokenService from '../../../services/tokenService';

describe('POST /refresh', () => {
  let app: any;

  const mockAccessToken =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const mockRefreshToken =
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MTA0ODQ4MDB9.4tC1L-4Q1g6K5ZQ7wY8z9X0vR1a2B3c4D5e6F7g8H9i0J';

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup jwt mocks
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

    jest.spyOn(jwt, 'sign').mockImplementation((_payload: any, _secret: any, _options: any) => {
      return mockAccessToken;
    });

    jest.spyOn(jwt, 'verify').mockImplementation((token: string) => {
      if (token === mockRefreshToken || token === mockAccessToken) {
        return {
          jti: 'mock-token-id',
          exp: Math.floor(Date.now() / 1000) + 60,
        };
      }
      throw new Error('Invalid token');
    });

    app = createTestApp();
  });

  it('should refresh tokens successfully', async () => {
    // Setup mocks for successful token refresh
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOneBy: jest.fn().mockResolvedValue({
        ...mockRegularPatient,
        role: Role.PATIENT,
      }),
    });

    (tokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
      userId: 1,
      jti: 'token-id',
      exp: Math.floor(Date.now() / 1000) + 3600,
      tokenVersionHash: 'mock-hash',
      fingerprint: 'mock-fingerprint',
    });

    (tokenService.rotateRefreshToken as jest.Mock).mockResolvedValue(mockRefreshToken);
    (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);

    const response = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', ['refreshToken=valid-refresh-token'])
      .set('User-Agent', 'test-agent');

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty('accessToken');
    expect(response.body).toHaveProperty('refreshToken');
    expect(response.headers['set-cookie']).toBeDefined();
  });

  it('should return 401 for missing refresh token', async () => {
    const response = await request(app).post('/api/auth/refresh');

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: 'Missing refresh token',
    });
  });

  it('should return 401 for invalid refresh token', async () => {
    (tokenService.verifyRefreshToken as jest.Mock).mockRejectedValueOnce(
      new Error('Invalid token')
    );

    const response = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', ['refreshToken=invalid-token']);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Invalid refresh token',
        status: 401,
      },
    });
  });

  it('should return 401 for expired refresh token', async () => {
    (tokenService.verifyRefreshToken as jest.Mock).mockRejectedValueOnce(
      new Error('Token has expired')
    );

    const response = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', ['refreshToken=expired-token']);

    expect(response.status).toBe(401);
    expect(response.body).toEqual({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Invalid refresh token',
        status: 401,
      },
    });
  });

  it('should return 404 when patient not found after token verification', async () => {
    (tokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
      userId: 999,
      jti: 'token-id',
      exp: Math.floor(Date.now() / 1000) + 3600,
      tokenVersionHash: 'mock-hash',
      fingerprint: 'mock-fingerprint',
    });

    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOneBy: jest.fn().mockResolvedValue(null),
    });

    const response = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', ['refreshToken=valid-refresh-token'])
      .set('User-Agent', 'test-agent');

    expect(response.status).toBe(404);
  });

  it('should return 500 when rotateRefreshToken returns undefined', async () => {
    (tokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
      userId: 1,
      jti: 'token-id',
      exp: Math.floor(Date.now() / 1000) + 3600,
      tokenVersionHash: 'mock-hash',
      fingerprint: 'mock-fingerprint',
    });

    (tokenService.rotateRefreshToken as jest.Mock).mockResolvedValue(undefined);

    const response = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', ['refreshToken=valid-refresh-token'])
      .set('User-Agent', 'test-agent');

    expect(response.status).toBe(500);
  });
});
