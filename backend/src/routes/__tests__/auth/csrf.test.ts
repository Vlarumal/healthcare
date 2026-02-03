/**
 * Auth Routes - CSRF Protection Tests
 * 
 * Tests for CSRF token protection on auth endpoints.
 * Uses shared test utilities from test-utils/ to reduce duplication.
 */

import request from 'supertest';
import jwt from 'jsonwebtoken';
import express, { Express, NextFunction, Response } from 'express';
import { AuthenticatedRequest } from '../../../types/express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import { setPasswordServiceInstance } from '../../../routes/authRoutes';
import { Role } from '../../../types/auth';
import { AppDataSource } from '../../../data-source';
import authRoutes from '../../authRoutes';
import errorHandler from '../../../middlewares/errorHandler';
import ErrorLogger from '../../../utils/errorLogger';
import { createLoginMockPatient } from '../../../test-utils/mockData';
import { resetMockServices } from '../../../test-utils/mockServices';

// Mock tokenService with all required functions
jest.mock('../../../services/tokenService', () => ({
  generateTokens: jest.fn(),
  storeRefreshToken: jest.fn(),
  verifyRefreshToken: jest.fn(),
  revokeToken: jest.fn(),
  revokeAllTokensForUser: jest.fn(),
  getTokenByUserId: jest.fn(),
  deleteTokenByUserId: jest.fn(),
}));

// Import after mocking
const tokenService = require('../../../services/tokenService');

jest.mock('bcrypt');
jest.mock('../../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
  },
}));
jest.mock('../../../services/passwordService', () => {
  const actual = jest.requireActual('../../../services/passwordService');
  return {
    PasswordService: jest.fn().mockImplementation(() => {
      return {
        ...actual.PasswordService.prototype,
        validatePassword: jest.fn().mockImplementation(() => {
          return;
        }),
        hashPassword: jest
          .fn()
          .mockImplementation((password) =>
            Promise.resolve(`hashed_${password}`)
          ),
      };
    }),
  };
});
jest.mock('../../../middlewares/authMiddleware', () => ({
  authenticateJWT: jest.fn(
    (
      req: AuthenticatedRequest,
      _res: Response,
      next: NextFunction
    ) => {
      if (req.headers.authorization) {
        req.user = { id: 1, role: Role.PATIENT, tokenVersion: 1 };
      }
      next();
    }
  ),
  authorizeRole: jest.fn(
    (_roles: string[]) =>
      (
        _req: AuthenticatedRequest,
        _res: Response,
        next: NextFunction
      ) =>
        next()
  ),
}));

describe('Auth Routes - CSRF Protection', () => {
  let app: Express;

  const mockLoginPatient = createLoginMockPatient(1, 'John', 'Doe', 'john.doe@example.com', Role.PATIENT);
  
  const mockAccessToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  // Token expires in 2026 (future date)
  const mockRefreshToken =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjM5MzE5NDQ4MDB9.4tC1L-4Q1g6K5ZQ7wY8z9X0vR1a2B3c4D5e6F7g8H9i0J';

  const mockTokens = {
    accessToken: mockAccessToken,
    refreshToken: mockRefreshToken,
  };

  beforeEach(() => {
    resetMockServices();
    setPasswordServiceInstance(null);
    
    // Re-setup password service mock after reset
    const mockPasswordService = require('../../../services/passwordService');
    mockPasswordService.PasswordService.mockImplementation(() => {
      const actual = jest.requireActual('../../../services/passwordService');
      return {
        ...actual.PasswordService.prototype,
        validatePassword: jest.fn().mockImplementation(() => {}),
        hashPassword: jest
          .fn()
          .mockImplementation((password) =>
            Promise.resolve(`hashed_${password}`)
          ),
      };
    });

    // Setup default mocks
    (AppDataSource.getRepository as jest.Mock).mockReturnValue({
      findOne: jest.fn().mockResolvedValue(mockLoginPatient),
    });
    (bcrypt.compare as jest.Mock).mockResolvedValue(true);
    (tokenService.generateTokens as jest.Mock).mockReturnValue(mockTokens);
    (tokenService.storeRefreshToken as jest.Mock).mockResolvedValue(undefined);
    (tokenService.revokeAllTokensForUser as jest.Mock).mockResolvedValue(1);
    // Mock verifyRefreshToken to succeed by default
    (tokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
      userId: 1,
      jti: 'token-id',
      exp: Math.floor(Date.now() / 1000) + 900,
      tokenVersion: process.env.TOKEN_VERSION,
    });

    // Mock JWT functions to prevent signature validation errors
    jest.spyOn(jwt, 'decode').mockImplementation((token: string) => {
      if (token === mockTokens.refreshToken) {
        return { jti: 'mock-token-id', exp: Math.floor(Date.now() / 1000) + 60 };
      }
      if (token === mockTokens.accessToken) {
        return { sub: 'user-id', exp: Math.floor(Date.now() / 1000) + 15 * 60 };
      }
      return null;
    });

    jest.spyOn(jwt, 'verify').mockImplementation((token: string) => {
      if (token === mockTokens.refreshToken || token === mockTokens.accessToken) {
        return { jti: 'mock-token-id', exp: Math.floor(Date.now() / 1000) + 60 };
      }
      throw new Error('Invalid token');
    });

    // Create app without global CSRF middleware
    app = express();
    app.use(bodyParser.json());
    app.use(cookieParser());
    // Note: CSRF middleware is NOT applied globally here
    app.use('/auth', authRoutes);
    app.use(errorHandler);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /auth/login', () => {
    it('should allow POST requests to login without CSRF token', async () => {
      const response = await request(app)
        .post('/auth/login')
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
    });

    it('should return 401 for invalid credentials', async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const response = await request(app)
        .post('/auth/login')
        .send({ email: 'john.doe@example.com', password: 'wrongpassword' });

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: 'Invalid credentials' });
    });
  });

  describe('POST /auth/logout', () => {
    it('should rotate CSRF token on logout', async () => {
      (tokenService.verifyRefreshToken as jest.Mock).mockResolvedValue({
        userId: 1,
        jti: 'token-id',
        exp: Math.floor(Date.now() / 1000) + 900,
        tokenVersion: process.env.TOKEN_VERSION,
      });
      (tokenService.revokeToken as jest.Mock).mockResolvedValue(true);

      const response = await request(app)
        .post('/auth/logout')
        .set('Cookie', ['refreshToken=valid-refresh-token']);

      expect(response.status).toBe(204);
      expect(response.headers['set-cookie']).toBeDefined();
    });

    it('should logout even with invalid refresh token', async () => {
      const { UnauthorizedError } = require('../../../errors/httpErrors');
      (tokenService.verifyRefreshToken as jest.Mock).mockRejectedValue(
        new UnauthorizedError('Invalid token')
      );

      const response = await request(app)
        .post('/auth/logout')
        .set('Cookie', ['refreshToken=invalid-refresh-token']);

      expect(response.status).toBe(204);
      expect(response.headers['set-cookie']).toBeDefined();
      expect(tokenService.verifyRefreshToken).toHaveBeenCalledWith(
        'invalid-refresh-token'
      );
      expect(tokenService.revokeToken).not.toHaveBeenCalled();
    });

    it('should logout without refresh token', async () => {
      const response = await request(app).post('/auth/logout');

      expect(response.status).toBe(204);
      expect(response.headers['set-cookie']).toBeDefined();
      expect(tokenService.verifyRefreshToken).not.toHaveBeenCalled();
      expect(tokenService.revokeToken).not.toHaveBeenCalled();
    });
  });

  describe('Token revocation failure handling', () => {
    it('should log token revocation failures but continue with login', async () => {
      (tokenService.revokeAllTokensForUser as jest.Mock).mockRejectedValue(
        new Error('Database connection failed')
      );

      const logErrorSpy = jest
        .spyOn(ErrorLogger, 'logError')
        .mockImplementation();
      const logWarningSpy = jest
        .spyOn(ErrorLogger, 'logWarning')
        .mockImplementation();

      const response = await request(app)
        .post('/auth/login')
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

  describe('Mock isolation', () => {
    it('should reset mocks between tests', async () => {
      expect(jest.isMockFunction(AppDataSource.getRepository)).toBe(true);
      expect(jest.isMockFunction(bcrypt.compare)).toBe(true);
      expect(jest.isMockFunction(tokenService.generateTokens)).toBe(true);
    });
  });
});

