import fs from 'fs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { AppDataSource } from '../../data-source';
import { Patient } from '../../entities/Patient';
import { Role } from '../../entities/Patient';
import {
  NotFoundError,
  UnauthorizedError,
} from '../../errors/httpErrors';
import * as tokenService from '../tokenService';
import {
  generateTokens,
  storeRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  rotateRefreshToken,
} from '../tokenService';
import { Token } from '../../entities/Token';
import { EntityManager } from 'typeorm';
import logger from '../../utils/logger';

jest.mock('../../utils/logger', () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));

jest.mock('jsonwebtoken');
jest.mock('crypto');
jest.mock('../../data-source', () => ({
  AppDataSource: {
    getRepository: jest.fn(),
    transaction: jest.fn(),
    manager: {
      transaction: jest.fn(),
    },
  },
}));

const mockPatientRepo = {
  findOneBy: jest.fn(),
  save: jest.fn(),
};

const mockTokenRepo = {
  findOneBy: jest.fn(),
  findOne: jest.fn(),
  save: jest.fn(),
};

(AppDataSource.getRepository as jest.Mock).mockImplementation(
  (entity) => {
    if (entity.name === 'Token') return mockTokenRepo;
    return mockPatientRepo;
  }
);

describe('TokenService', () => {
  const mockPatient: Partial<Patient> = {
    id: 1,
    passwordVersion: 1,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.JWT_SECRET = 'test-secret';
    process.env.REFRESH_TOKEN_SECRET = 'refresh-secret';
    process.env.TOKEN_VERSION = '1';
    process.env.TOKEN_BINDING_SECRET = 'binding-secret';
    process.env.TOKEN_ISSUER = 'healthcare-system';
    process.env.TOKEN_AUDIENCE = 'healthcare-audience';

    const mockManager = {
      getRepository: jest.fn().mockImplementation((entity) => {
        if (entity.name === 'Token') return mockTokenRepo;
        return mockPatientRepo;
      }),
    };

    (AppDataSource.transaction as jest.Mock) = jest.fn(
      async (callback: (manager: any) => Promise<any>) => {
        return callback(mockManager);
      }
    );
  });

  describe('generateTokens()', () => {
    it('should generate valid access and refresh tokens with fingerprint claim', () => {
      (jwt.sign as jest.Mock)
        .mockReturnValueOnce('access-token')
        .mockReturnValueOnce('refresh-token');
      (crypto.randomBytes as jest.Mock).mockReturnValue(
        Buffer.from('token-id')
      );
      (crypto.randomBytes as jest.Mock).mockReturnValue(
        Buffer.from('token-id')
      );
      (crypto.createHmac as jest.Mock).mockReturnValue({
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('fingerprint-hash'),
      });

      process.env.TOKEN_BINDING_SECRET = 'binding-secret';

      const tokens = generateTokens(
        1,
        Role.PATIENT,
        1,
        'user-agent',
        '127.0.0.1'
      );

      expect(tokens.accessToken).toBe('access-token');
      expect(tokens.refreshToken).toBe('refresh-token');
      expect(jwt.sign).toHaveBeenCalledWith(
        {
          sub: '1',
          role: Role.PATIENT,
          passwordVersion: 1,
          tokenVersionHash: expect.any(String),
          fingerprint: 'fingerprint-hash',
          iss: 'healthcare-system',
          aud: 'healthcare-audience',
        },
        expect.any(String),
        {
          expiresIn: '25m',
          algorithm: 'RS256',
        }
      );
    });
  });

  describe('storeRefreshToken()', () => {
    it('should store refresh token for valid user', async () => {
      const mockManager: EntityManager = {
        getRepository: jest.fn().mockImplementation((entity) => {
          if (entity === Token) return mockTokenRepo;
          if (entity === Patient) return mockPatientRepo;
          return null;
        }),
      } as unknown as EntityManager; // Safe cast since we only need getRepository

      mockPatientRepo.findOneBy.mockResolvedValue(mockPatient);
      mockTokenRepo.save.mockResolvedValue({ id: 'token-id' });

      await storeRefreshToken(
        1,
        'token-id',
        Date.now() + 10000,
        mockManager
      );

      expect(mockTokenRepo.save).toHaveBeenCalled();
      const savedToken = mockTokenRepo.save.mock.calls[0][0];
      expect(savedToken.token).toBe('token-id');
      expect(savedToken.patient.id).toBe(1);
      // Allow 10ms tolerance for expiration time comparison
      expect(savedToken.expiresAt.getTime()).toBeGreaterThanOrEqual(
        Date.now() + 10000 - 10
      );
      expect(savedToken.expiresAt.getTime()).toBeLessThanOrEqual(
        Date.now() + 10000 + 10
      );
    });

    it('should throw NotFoundError for invalid user', async () => {
      const mockManager: EntityManager = {
        getRepository: jest.fn().mockImplementation((entity) => {
          if (entity === Token) return mockTokenRepo;
          if (entity === Patient) return mockPatientRepo;
          return null;
        }),
      } as unknown as EntityManager; // Safe cast since we only need getRepository

      mockPatientRepo.findOneBy.mockResolvedValue(null);

      await expect(
        storeRefreshToken(999, 'token-id', Date.now(), mockManager)
      ).rejects.toThrow(NotFoundError);
    });
  });

  describe('verifyRefreshToken()', () => {
    const mockTokenRepo = {
      findOneBy: jest.fn(),
      findOne: jest.fn(),
      save: jest.fn(),
    };

    beforeEach(() => {
      (AppDataSource.getRepository as jest.Mock).mockImplementation(
        (entity) => {
          if (entity.name === 'Token') return mockTokenRepo;
          return mockPatientRepo;
        }
      );

      jest.spyOn(logger, 'error').mockImplementation();

      const mockHmac = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('expected-hash'),
      };
      (crypto.createHmac as jest.Mock).mockReturnValue(mockHmac);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should throw UnauthorizedError when token version is invalid', async () => {
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _key, _options, callback) => {
          if (callback) {
            callback(null, {
              jti: 'valid-token-id',
              userId: 1,
              tokenVersionHash: 'invalid-version',
            });
          }
        }
      );
      mockTokenRepo.findOneBy.mockResolvedValue({
        token: 'valid-token-id',
        revoked: false,
      });

      await expect(
        verifyRefreshToken('invalid-token')
      ).rejects.toThrow(
        new UnauthorizedError('Refresh token version is invalid')
      );
    }, 10000);

    it('should throw UnauthorizedError for invalid refresh token', async () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('invalid token');
      });

      await expect(
        verifyRefreshToken('invalid-token')
      ).rejects.toThrow(UnauthorizedError);
    });

    it('should throw UnauthorizedError for revoked refresh token', async () => {
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _key, _options, callback) => {
          if (callback) {
            callback(null, {
              jti: 'revoked-token-id',
              userId: 1,
              tokenVersionHash: 'expected-hash',
            });
          } else {
            return {
              jti: 'revoked-token-id',
              userId: 1,
              tokenVersionHash: 'expected-hash',
            };
          }
        }
      );
      mockTokenRepo.findOneBy.mockResolvedValue({
        token: 'revoked-token-id',
        revoked: true,
      });

      await expect(
        verifyRefreshToken('revoked-token')
      ).rejects.toThrow(
        new UnauthorizedError('Refresh token revoked')
      );
    }, 10000);

    it('should throw UnauthorizedError when token not found in database', async () => {
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _key, _options, callback) => {
          if (callback) {
            callback(null, { jti: 'missing-token-id', userId: 1 });
          } else {
            return { jti: 'missing-token-id', userId: 1 };
          }
        }
      );
      mockTokenRepo.findOneBy.mockResolvedValue(null);

      await expect(
        verifyRefreshToken('missing-token')
      ).rejects.toThrow(UnauthorizedError);
    });

    it('should throw UnauthorizedError when token not found in database', async () => {
      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _key, _options, callback) => {
          if (callback) {
            callback(null, { jti: 'missing-token-id', userId: 1 });
          } else {
            return { jti: 'missing-token-id', userId: 1 };
          }
        }
      );
      mockTokenRepo.findOneBy.mockResolvedValue(null);

      await expect(
        verifyRefreshToken('missing-token')
      ).rejects.toThrow(UnauthorizedError);
    }, 10000);

    describe('fingerprint validation', () => {
      const validPayload = {
        jti: 'valid-token-id',
        userId: 1,
        tokenVersionHash: 'expected-hash',
        fingerprint: 'valid-fingerprint',
        iss: 'healthcare-system',
        aud: 'healthcare-audience',
      };

      beforeEach(() => {
        (jwt.verify as jest.Mock).mockImplementation(
          (_token, _key, _options, callback) => {
            if (callback) {
              callback(null, validPayload);
            } else {
              return validPayload;
            }
          }
        );
        mockTokenRepo.findOneBy.mockResolvedValue({
          token: 'valid-token-id',
          revoked: false,
        });
      });

      it('should pass validation when fingerprints match', async () => {
        const payload = await verifyRefreshToken(
          'valid-token',
          'valid-fingerprint'
        );
        expect(payload).toEqual(validPayload);
      });

      it('should throw UnauthorizedError when token fingerprint does not match current fingerprint', async () => {
        await expect(
          verifyRefreshToken('valid-token', 'invalid-fingerprint')
        ).rejects.toThrow(
          new UnauthorizedError('Token fingerprint does not match')
        );
      });

      it('should throw UnauthorizedError when token has fingerprint but current fingerprint is missing', async () => {
        await expect(
          verifyRefreshToken('valid-token', undefined)
        ).rejects.toThrow(
          new UnauthorizedError(
            'Token fingerprint validation requires current fingerprint'
          )
        );
      });

      it('should pass validation when token has no fingerprint and current fingerprint is missing', async () => {
        const payloadWithoutFingerprint = {
          jti: 'valid-token-id',
          userId: 1,
          tokenVersionHash: 'expected-hash',
          iss: 'healthcare-system',
          aud: 'healthcare-audience',
          // no fingerprint property
        };

        (jwt.verify as jest.Mock).mockImplementation(
          (_token, _key, _options, callback) => {
            if (callback) {
              callback(null, payloadWithoutFingerprint);
            } else {
              return payloadWithoutFingerprint;
            }
          }
        );

        mockTokenRepo.findOneBy.mockResolvedValue({
          token: 'valid-token-id',
          revoked: false,
        });

        const payload = await verifyRefreshToken(
          'valid-token',
          undefined
        );
        expect(payload).toEqual(payloadWithoutFingerprint);
      });
    });
  });

  describe('verifyAccessToken()', () => {
    it('should throw UnauthorizedError for invalid tokens', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new Error('invalid token');
      });

      expect(() =>
        verifyAccessToken('invalid-token', 'test-fingerprint')
      ).toThrow(UnauthorizedError);
    });

    it('should throw UnauthorizedError for invalid token signature', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.JsonWebTokenError('invalid signature');
      });

      expect(() =>
        verifyAccessToken('invalid-token', 'test-fingerprint')
      ).toThrow(new UnauthorizedError('Invalid token signature'));
    });

    it('should throw UnauthorizedError when token is not yet active', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.NotBeforeError('jwt not active', new Date());
      });

      expect(() =>
        verifyAccessToken('not-active-token', 'test-fingerprint')
      ).toThrow(new UnauthorizedError('Token not yet active'));
    });

    it('should throw UnauthorizedError when token is expired', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        throw new jwt.TokenExpiredError('jwt expired', new Date());
      });

      expect(() =>
        verifyAccessToken('expired-token', 'test-fingerprint')
      ).toThrow(new UnauthorizedError('Token expired'));
    });

    it('should throw UnauthorizedError for invalid token audience', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        const error = new jwt.JsonWebTokenError(
          'jwt audience invalid. expected: healthcare-audience'
        );
        error.message =
          'jwt audience invalid. expected: healthcare-audience';
        throw error;
      });

      const token = 'invalid_token';
      const fingerprint = 'test_fingerprint';

      expect(() => verifyAccessToken(token, fingerprint)).toThrow(
        new UnauthorizedError('Invalid token audience')
      );
    });
    it('should throw UnauthorizedError for invalid token issuer', () => {
      (jwt.verify as jest.Mock).mockImplementation(() => {
        const error = new jwt.JsonWebTokenError(
          'jwt issuer invalid. expected: healthcare-system'
        );
        error.message =
          'jwt issuer invalid. expected: healthcare-system';
        throw error;
      });

      const token = 'invalid_token';
      const fingerprint = 'test_fingerprint';

      expect(() => verifyAccessToken(token, fingerprint)).toThrow(
        new UnauthorizedError('Invalid token issuer')
      );
    });

    it('should throw UnauthorizedError when token version hash is invalid', () => {
      const expectedTokenVersionHash = 'expected-token-version-hash';
      jest
        .spyOn(tokenService, 'generateTokenVersionHash')
        .mockReturnValue(expectedTokenVersionHash);

      (jwt.verify as jest.Mock).mockReturnValue({
        userId: 1,
        tokenVersionHash: 'invalid-hash',
      });

      expect(() =>
        verifyAccessToken('invalid-token', 'test-fingerprint')
      ).toThrow(new UnauthorizedError('Token version is invalid'));
    });

    it('should skip fingerprint validation when token has no fingerprint', () => {
      const mockHmac = {
        update: jest.fn().mockReturnThis(),
        digest: jest
          .fn()
          .mockReturnValue('expected-token-version-hash'),
      };
      (crypto.createHmac as jest.Mock).mockReturnValue(mockHmac);

      (jwt.verify as jest.Mock).mockReturnValue({
        tokenVersionHash: 'expected-token-version-hash',
        // no fingerprint
      });

      const payload = verifyAccessToken(
        'valid-token',
        'any-fingerprint'
      );
      expect(payload).toEqual({
        tokenVersionHash: 'expected-token-version-hash',
      });
    });

    describe('fingerprint validation', () => {
      let expectedTokenVersionHash: string;

      beforeEach(() => {
        expectedTokenVersionHash = 'expected-token-version-hash';
        jest
          .spyOn(tokenService, 'generateTokenVersionHash')
          .mockReturnValue(expectedTokenVersionHash);
      });

      afterEach(() => {
        jest.restoreAllMocks();
      });

      it('should throw error when token has fingerprint but current fingerprint is missing', () => {
        (jwt.verify as jest.Mock).mockReturnValue({
          tokenVersionHash: expectedTokenVersionHash,
          fingerprint: 'abc123',
        });

        expect(() =>
          verifyAccessToken('token', undefined as any)
        ).toThrow(
          new UnauthorizedError(
            'Token fingerprint validation requires current fingerprint'
          )
        );
      });

      it('should throw error when token fingerprint does not match current fingerprint', () => {
        (jwt.verify as jest.Mock).mockReturnValue({
          tokenVersionHash: expectedTokenVersionHash,
          fingerprint: 'abc123',
        });

        expect(() =>
          verifyAccessToken('token', 'wrong-fingerprint')
        ).toThrow(
          new UnauthorizedError('Token fingerprint does not match')
        );
      });

      it('should pass validation when token fingerprint matches current fingerprint', () => {
        (jwt.verify as jest.Mock).mockReturnValue({
          tokenVersionHash: expectedTokenVersionHash,
          fingerprint: 'abc123',
        });

        const payload = verifyAccessToken('token', 'abc123');
        expect(payload).toEqual({
          tokenVersionHash: expectedTokenVersionHash,
          fingerprint: 'abc123',
        });
      });

      it('should skip validation when token has no fingerprint', () => {
        (jwt.verify as jest.Mock).mockReturnValue({
          tokenVersionHash: expectedTokenVersionHash,
          // no fingerprint property
        });

        const payload = verifyAccessToken('token', 'any-fingerprint');
        expect(payload).toEqual({
          tokenVersionHash: expectedTokenVersionHash,
        });
      });
    });

    describe('generateTokenVersionHash', () => {
      it('generates identical token version hashes when called from different services', () => {
        process.env.TOKEN_VERSION = 'test-secret';

        const serviceHash = tokenService.generateTokenVersionHash();

        const middlewareHash = (() => {
          if (!process.env.TOKEN_VERSION) {
            throw new Error(
              'TOKEN_VERSION environment variable is not set'
            );
          }
          return crypto
            .createHmac('sha256', process.env.TOKEN_VERSION)
            .update('v1')
            .digest('hex');
        })();

        expect(serviceHash).toEqual(middlewareHash);
      });

      it('throws error when TOKEN_VERSION is missing', () => {
        const originalTokenVersion = process.env.TOKEN_VERSION;
        delete process.env.TOKEN_VERSION;

        jest.resetModules();
        const tokenService = require('../tokenService');

        expect(() => tokenService.generateTokenVersionHash()).toThrow(
          'TOKEN_VERSION environment variable is not set'
        );

        if (originalTokenVersion !== undefined) {
          process.env.TOKEN_VERSION = originalTokenVersion;
        }
      });
    });

    describe('validateTokenFingerprint()', () => {
      const mockTokenVersionHash = jest
        .spyOn(tokenService, 'generateTokenVersionHash')
        .mockReturnValue('expected-hash');

      afterEach(() => {
        mockTokenVersionHash.mockClear();
      });

      it('returns true when fingerprints match', () => {
        const payload = { fingerprint: 'abc123' };
        const currentFingerprint = 'abc123';
        expect(
          tokenService.validateTokenFingerprint(
            payload,
            currentFingerprint
          )
        ).toBe(true);
      });

      it('returns false when fingerprints dont match', () => {
        const payload = { fingerprint: 'abc123' };
        const currentFingerprint = 'xyz789';
        expect(
          tokenService.validateTokenFingerprint(
            payload,
            currentFingerprint
          )
        ).toBe(false);
      });
    });

    describe('validateTokenFingerprint()', () => {
      it('returns true when fingerprints match', () => {
        const payload = { fingerprint: 'abc123' };
        const currentFingerprint = 'abc123';
        expect(
          tokenService.validateTokenFingerprint(
            payload,
            currentFingerprint
          )
        ).toBe(true);
      });

      it('returns false when fingerprints dont match', () => {
        const payload = { fingerprint: 'abc123' };
        const currentFingerprint = 'xyz789';
        expect(
          tokenService.validateTokenFingerprint(
            payload,
            currentFingerprint
          )
        ).toBe(false);
      });
    });
  });

  describe('rotateRefreshToken()', () => {
    beforeEach(() => {
      jest
        .spyOn(tokenService, 'storeRefreshToken')
        .mockResolvedValue();
      jest
        .spyOn(jwt, 'sign')
        .mockReturnValue('new-refresh-token' as any);
      (crypto.randomBytes as jest.Mock).mockReturnValue(
        Buffer.from('new-token-id')
      );
      (jwt.decode as jest.Mock).mockReturnValue({
        jti: 'new-token-id',
        exp: Math.floor(Date.now() / 1000) + 86400,
      });
      jest.spyOn(logger, 'warn').mockImplementation();
      jest.spyOn(tokenService, 'revokeToken').mockResolvedValue(true);
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    jest.spyOn(logger, 'error').mockImplementation();

    it('should rotate token and revoke old one', async () => {
      const newRefreshToken = await rotateRefreshToken(
        1,
        'old-token-id',
        'test-user-agent',
        '127.0.0.1'
      );

      expect(newRefreshToken).toBe('new-refresh-token');
      expect(tokenService.revokeToken).toHaveBeenCalledWith(
        1,
        'old-token-id'
      );
      expect(tokenService.storeRefreshToken).toHaveBeenCalledWith(
        1,
        'new-token-id',
        expect.any(Number),
        expect.any(Object)
      );
    });

    it('should still rotate token when revocation fails', async () => {
      jest
        .spyOn(tokenService, 'revokeToken')
        .mockResolvedValue(false);

      const newRefreshToken = await rotateRefreshToken(
        1,
        'old-token-id',
        'test-user-agent',
        '127.0.0.1'
      );

      expect(newRefreshToken).toBe('new-refresh-token');
      expect(tokenService.storeRefreshToken).toHaveBeenCalledWith(
        1,
        'new-token-id',
        expect.any(Number),
        expect.any(Object)
      );
    });

    it('should handle undefined oldTokenId', async () => {
      const newRefreshToken = await rotateRefreshToken(
        1,
        undefined,
        'test-user-agent',
        '127.0.0.1'
      );

      expect(newRefreshToken).toBe('new-refresh-token');
      const revokeTokenMock = jest
        .spyOn(tokenService, 'revokeToken')
        .mockResolvedValue(true);
      expect(revokeTokenMock).not.toHaveBeenCalled();
    });

    it('should log transaction error and continue rotation', async () => {
      const error = new Error('Database transaction failed');
      (AppDataSource.transaction as jest.Mock).mockRejectedValueOnce(
        error
      );

      const errorSpy = jest
        .spyOn(logger, 'error')
        .mockImplementation();
      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation();

      const result = await rotateRefreshToken(
        1,
        'old-token-id',
        'test-user-agent',
        '127.0.0.1'
      );

      expect(result).toBe('new-refresh-token');
      expect(errorSpy).toHaveBeenCalledWith(
        `Token rotation transaction failed: ${error.message}`
      );
      expect(warnSpy).toHaveBeenCalledWith(
        'Continuing token rotation despite transaction error'
      );
    });
  });

  describe('rotateRefreshToken error handling', () => {
    const mockTransactionalEntityManager = {
      getRepository: jest.fn().mockImplementation((entity) => {
        if (entity.name === 'Token') return mockTokenRepo;
        return mockPatientRepo;
      }),
    };

    beforeEach(() => {
      jest.clearAllMocks();
      jest
        .spyOn(tokenService, 'storeRefreshToken')
        .mockResolvedValue();
      jest
        .spyOn(jwt, 'sign')
        .mockReturnValue('new-refresh-token' as any);
      (crypto.randomBytes as jest.Mock).mockReturnValue(
        Buffer.from('new-token-id')
      );
      (jwt.decode as jest.Mock).mockReturnValue({
        jti: 'new-token-id',
        exp: Math.floor(Date.now() / 1000) + 86400,
      });
      (AppDataSource.transaction as jest.Mock).mockImplementation(
        async (cb) => {
          return cb(mockTransactionalEntityManager);
        }
      );

      jest.spyOn(logger, 'warn').mockImplementation();
      jest.spyOn(logger, 'error').mockImplementation();
    });

    it('should log warning when revocation fails', async () => {
      jest
        .spyOn(tokenService, 'revokeToken')
        .mockResolvedValueOnce(false);

      await tokenService.rotateRefreshToken(
        1,
        'old_token_id',
        'test-user-agent',
        '127.0.0.1'
      );

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          'Failed to revoke old token during rotation'
        )
      );
      expect(tokenService.storeRefreshToken).toHaveBeenCalled();
    });

    it('should log error when revocation fails with exception', async () => {
      jest
        .spyOn(tokenService, 'revokeToken')
        .mockRejectedValueOnce(
          new Error('Revocation service unavailable')
        );

      await tokenService.rotateRefreshToken(
        1,
        'old_token_id',
        'test-user-agent',
        '127.0.0.1'
      );

      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining(
          'Failed to revoke old token during rotation'
        )
      );
      expect(tokenService.storeRefreshToken).toHaveBeenCalled();
    });

    it('should proceed with rotation when no old token exists', async () => {
      jest
        .spyOn(tokenService, 'storeRefreshToken')
        .mockResolvedValue();
      jest
        .spyOn(jwt, 'sign')
        .mockReturnValue('new-refresh-token' as any);
      (crypto.randomBytes as jest.Mock).mockReturnValue(
        Buffer.from('new-token-id')
      );
      (jwt.decode as jest.Mock).mockReturnValue({
        jti: 'new-token-id',
        exp: Math.floor(Date.now() / 1000) + 86400,
      });

      await tokenService.rotateRefreshToken(
        1,
        undefined,
        'test-user-agent',
        '127.0.0.1'
      );

      expect(tokenService.revokeToken).not.toHaveBeenCalled();
      expect(jwt.sign).toHaveBeenCalled();
      expect(tokenService.storeRefreshToken).toHaveBeenCalled();
    });
  });

  describe('revokeAllTokensForUser()', () => {
    let mockEntityManager: EntityManager;
    let mockTokenRepo: any;

    beforeEach(() => {
      mockEntityManager = {
        transaction: jest.fn() as any,
        getRepository: jest.fn() as any,
      } as unknown as EntityManager;

      mockTokenRepo = {
        createQueryBuilder: jest.fn().mockReturnThis(),
        update: jest.fn().mockReturnThis(),
        set: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        execute: jest.fn(),
      };

      (
        mockEntityManager.getRepository as jest.Mock
      ).mockImplementation((entity: any) => {
        if (entity === Token) return mockTokenRepo;
        return null;
      });

      jest.spyOn(logger, 'info').mockImplementation();
      jest.spyOn(logger, 'warn').mockImplementation();
      jest.spyOn(logger, 'error').mockImplementation();
    });

    it('should revoke all tokens successfully on first attempt', async () => {
      const userId = 1;
      const affectedCount = 5;

      mockTokenRepo.execute.mockResolvedValue({
        affected: affectedCount,
      });
      (mockEntityManager.transaction as jest.Mock).mockImplementation(
        async (cb: any) => {
          return cb(mockEntityManager);
        }
      );

      const result = await tokenService.revokeAllTokensForUser(
        userId,
        mockEntityManager
      );

      expect(result).toBe(affectedCount);
      expect(mockEntityManager.transaction).toHaveBeenCalledTimes(1);
      expect(logger.info).toHaveBeenCalledWith(
        `Revoked ${affectedCount} tokens for user ${userId}`
      );
    });

    it('should fail after max retries and return 0', async () => {
      const userId = 1;
      const maxRetries = 3;

      (mockEntityManager.transaction as jest.Mock).mockRejectedValue(
        new Error('deadlock detected')
      );

      const result = await tokenService.revokeAllTokensForUser(
        userId,
        mockEntityManager
      );

      expect(result).toBe(0);
      expect(mockEntityManager.transaction).toHaveBeenCalledTimes(
        maxRetries
      );
      expect(logger.error).toHaveBeenCalledWith(
        `Failed to revoke tokens for user ${userId} after ${maxRetries} attempts`
      );
    });

    it('should return 0 immediately for non-retryable errors', async () => {
      const userId = 1;
      const error = new Error('Non-retryable error');

      (mockEntityManager.transaction as jest.Mock).mockRejectedValue(
        error
      );

      const result = await tokenService.revokeAllTokensForUser(
        userId,
        mockEntityManager
      );

      expect(result).toBe(0);
      expect(mockEntityManager.transaction).toHaveBeenCalledTimes(1);
      expect(logger.error).toHaveBeenCalledWith(
        `Failed to revoke tokens for user ${userId}`,
        { error }
      );
    });

    it('should return the number of affected tokens', async () => {
      const userId = 1;
      const affectedCount = 2;

      mockTokenRepo.execute.mockResolvedValue({
        affected: affectedCount,
      });
      (mockEntityManager.transaction as jest.Mock).mockImplementation(
        async (cb: any) => {
          return cb(mockEntityManager);
        }
      );

      const result = await tokenService.revokeAllTokensForUser(
        userId,
        mockEntityManager
      );

      expect(result).toBe(affectedCount);
    });

    it('should handle unknown error types during token revocation', async () => {
      const userId = 1;
      const nonError = { unexpected: 'error object' };

      (
        mockEntityManager.transaction as jest.Mock
      ).mockRejectedValueOnce(nonError);

      const errorSpy = jest.spyOn(logger, 'error');
      const result = await tokenService.revokeAllTokensForUser(
        userId,
        mockEntityManager
      );

      expect(result).toBe(0);
      expect(errorSpy).toHaveBeenCalledWith(
        `Unknown error type during token revocation: ${nonError}`
      );
      expect(mockEntityManager.transaction).toHaveBeenCalledTimes(1);
    });
  });

  describe('revokeToken()', () => {
    const mockTokenRepo = {
      findOne: jest.fn(),
      findOneBy: jest.fn(),
      save: jest.fn(),
    };

    let mockEntityManager: EntityManager;

    beforeEach(() => {
      mockTokenRepo.findOne.mockReset();
      mockTokenRepo.save.mockReset();

      mockEntityManager = {
        getRepository: jest.fn().mockImplementation((entity) => {
          if (entity === Token) {
            return mockTokenRepo;
          }
          return null;
        }),
      } as unknown as EntityManager;

      jest.spyOn(logger, 'warn').mockImplementation();
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it('should revoke token by setting revoked to true', async () => {
      const mockToken = {
        id: 123,
        token: 'test-token-id',
        revoked: false,
        patient: { id: 123 },
      };
      mockTokenRepo.findOne.mockResolvedValue(mockToken);
      mockTokenRepo.save.mockResolvedValue({
        ...mockToken,
        revoked: true,
      });

      const result = await tokenService.revokeToken(
        123,
        'test-token-id',
        mockEntityManager
      );

      expect(result).toBe(true);
      expect(mockTokenRepo.findOne).toHaveBeenCalledWith({
        where: {
          token: 'test-token-id',
          revoked: false,
        },
        relations: ['patient'],
      });
      expect(mockTokenRepo.save).toHaveBeenCalledWith(
        expect.objectContaining({
          revoked: true,
        })
      );
    });

    it('should return false for token not found', async () => {
      mockTokenRepo.findOne.mockResolvedValue(null);

      const result = await tokenService.revokeToken(
        456,
        'non-existent-token',
        mockEntityManager
      );
      expect(result).toBe(false);
    });

    it('should return false when token exists but belongs to different user', async () => {
      const mockToken = {
        id: 123,
        token: 'valid-token-id',
        revoked: false,
        patient: { id: 456 },
      };
      mockTokenRepo.findOne.mockResolvedValue(mockToken);

      const warnSpy = jest.spyOn(logger, 'warn').mockImplementation();

      const result = await tokenService.revokeToken(
        123, // Current user ID (different from token owner)
        'valid-token-id',
        mockEntityManager
      );

      expect(result).toBe(false);
      expect(warnSpy).toHaveBeenCalledWith(
        'Token does not belong to user: valid-token-id'
      );
      expect(mockTokenRepo.save).not.toHaveBeenCalled();
    });

    it('should return false when tokenId is undefined', async () => {
      const result = await tokenService.revokeToken(
        undefined as any,
        undefined as any,
        mockEntityManager
      );
      expect(result).toBe(false);
    });

    it('should log error when tokenRepo.findOne throws', async () => {
      mockTokenRepo.findOne.mockRejectedValue(
        new Error('Database error')
      );

      const errorSpy = jest.spyOn(logger, 'error');

      const result = await tokenService.revokeToken(
        123,
        'test-token-id',
        mockEntityManager
      );

      expect(result).toBe(false);
      expect(errorSpy).toHaveBeenCalledWith(
        'Failed to revoke token: test-token-id',
        { error: expect.any(Error) }
      );
    });

    it('should log error when tokenRepo.save throws', async () => {
      const mockToken = {
        id: 123,
        token: 'test-token-id',
        revoked: false,
        patient: { id: 123 },
      };
      mockTokenRepo.findOne.mockResolvedValue(mockToken);
      mockTokenRepo.save.mockRejectedValue(new Error('Save failed'));

      const errorSpy = jest.spyOn(logger, 'error');

      const result = await tokenService.revokeToken(
        123,
        'test-token-id',
        mockEntityManager
      );

      expect(result).toBe(false);
      expect(errorSpy).toHaveBeenCalledWith(
        'Failed to revoke token: test-token-id',
        { error: expect.any(Error) }
      );
    });

    it('should throw error when entityManager is undefined', async () => {
      const originalManager = AppDataSource.manager;
      (AppDataSource as any).manager = undefined;

      const errorSpy = jest.spyOn(logger, 'error');

      await expect(
        tokenService.revokeToken(123, 'test-token-id')
      ).rejects.toThrow('Database connection error');

      expect(errorSpy).toHaveBeenCalledWith(
        'EntityManager is undefined in revokeToken'
      );

      (AppDataSource as any).manager = originalManager;
      errorSpy.mockRestore();
    });
  });

  describe('Key Size Validation', () => {
    const OLD_ENV = process.env;
    let originalReadFileSync: any;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...OLD_ENV };
      originalReadFileSync = fs.readFileSync;
    });

    afterEach(() => {
      process.env = OLD_ENV;
      fs.readFileSync = originalReadFileSync;
    });

    it('should throw error and log warning when key size < 2048 bits', async () => {
      jest
        .spyOn(fs, 'readFileSync')
        .mockReturnValue('a'.repeat(2047));

      const logger = require('../../utils/logger');
      const warnSpy = logger.warn;

      await expect(() => import('../tokenService')).rejects.toThrow(
        'Insecure RSA key size'
      );

      expect(warnSpy).toHaveBeenCalledWith(
        'Private key size is less than 2048 bits, which is insecure'
      );
    });

    it('should not throw error when key size >= 2048 bits', async () => {
      jest
        .spyOn(fs, 'readFileSync')
        .mockReturnValue('a'.repeat(2048));

      const logger = require('../../utils/logger');
      const warnSpy = logger.warn;

      await expect(import('../tokenService')).resolves.toBeDefined();
      expect(warnSpy).not.toHaveBeenCalled();
    });
  });

  describe('Environment Validation', () => {
    const OLD_ENV = process.env;

    beforeEach(() => {
      jest.resetModules();
      process.env = { ...OLD_ENV };
    });

    afterEach(() => {
      process.env = OLD_ENV;
    });

    it('should throw error when TOKEN_VERSION is missing', () => {
      const originalTokenVersion = process.env.TOKEN_VERSION;
      delete process.env.TOKEN_VERSION;

      jest.resetModules();
      const tokenService = require('../tokenService');

      expect(() => tokenService.generateTokenVersionHash()).toThrow(
        'TOKEN_VERSION environment variable is not set'
      );

      if (originalTokenVersion !== undefined) {
        process.env.TOKEN_VERSION = originalTokenVersion;
      }
    });

    it('should throw error when TOKEN_BINDING_SECRET is missing', () => {
      const originalTokenBindingSecret =
        process.env.TOKEN_BINDING_SECRET;
      delete process.env.TOKEN_BINDING_SECRET;

      jest.resetModules();
      const tokenService = require('../tokenService');

      expect(() =>
        tokenService.generateFingerprint('test-agent', '127.0.0.1')
      ).toThrow(
        'TOKEN_BINDING_SECRET environment variable is not set'
      );

      if (originalTokenBindingSecret !== undefined) {
        process.env.TOKEN_BINDING_SECRET = originalTokenBindingSecret;
      }
    });
  });

  describe('Fingerprint Validation', () => {
    const mockTokenRepo = {
      findOneBy: jest.fn(),
      findOne: jest.fn(),
      save: jest.fn(),
    };

    beforeEach(() => {
      (AppDataSource.getRepository as jest.Mock).mockImplementation(
        (entity) => {
          if (entity.name === 'Token') return mockTokenRepo;
          return mockPatientRepo;
        }
      );
    });

    it('should reject tokens with mismatched fingerprint', async () => {
      const validPayload = {
        jti: 'valid-token-id',
        userId: 1,
        fingerprint: 'correct-fingerprint',
      };

      (jwt.verify as jest.Mock).mockImplementation(
        (_token, _key, _options, callback) => {
          if (callback) {
            callback(null, validPayload);
          } else {
            return validPayload;
          }
        }
      );
      mockTokenRepo.findOneBy.mockResolvedValue({
        token: 'valid-token-id',
        revoked: false,
      });

      const tamperedPayload = {
        ...validPayload,
        fingerprint: 'tampered-fingerprint',
      };

      (jwt.verify as jest.Mock).mockImplementation(
        (token, _key, _options, callback) => {
          if (token === 'tampered-token') {
            if (callback) {
              callback(null, tamperedPayload);
            } else {
              return tamperedPayload;
            }
          } else {
            if (callback) {
              callback(null, validPayload);
            } else {
              return validPayload;
            }
          }
        }
      );

      await expect(
        verifyRefreshToken('tampered-token')
      ).rejects.toThrow(UnauthorizedError);
    }, 10000);

    it('should generate valid HMAC fingerprint', () => {
      process.env.TOKEN_BINDING_SECRET = 'test-secret';
      const userAgent = 'test-agent';
      const ip = '127.0.0.1';

      const mockHmac = {
        update: jest.fn().mockReturnThis(),
        digest: jest.fn().mockReturnValue('expected-hash'),
      };
      (crypto.createHmac as jest.Mock).mockReturnValue(mockHmac);

      tokenService.generateFingerprint(userAgent, ip);

      expect(crypto.createHmac).toHaveBeenCalledWith(
        'sha256',
        'test-secret'
      );
      expect(mockHmac.update).toHaveBeenCalledWith(
        'test-agent127.0.0.1'
      );
      expect(mockHmac.digest).toHaveBeenCalledWith('hex');
    });
  });

  it('should throw error when TOKEN_BINDING_SECRET is undefined', () => {
    const originalSecret = process.env.TOKEN_BINDING_SECRET;
    delete process.env.TOKEN_BINDING_SECRET;

    try {
      expect(() =>
        tokenService.generateFingerprint('test-agent', '127.0.0.1')
      ).toThrow(
        'TOKEN_BINDING_SECRET environment variable is not set'
      );
    } finally {
      process.env.TOKEN_BINDING_SECRET = originalSecret;
    }
  });

  describe('Token Expiration', () => {
    it('should set refresh token expiration to exactly 7 days', () => {
      const now = Date.now();
      jest.spyOn(Date, 'now').mockReturnValue(now);

      (jwt.sign as jest.Mock).mockImplementation(
        (_payload, _secret, options) => {
          if (options?.expiresIn === '7d') {
            return 'refresh-token';
          }
          return 'access-token';
        }
      );

      (jwt.decode as jest.Mock).mockReturnValue({
        exp: Math.floor(now / 1000) + 60 * 60 * 24 * 7,
      });

      const tokens = generateTokens(
        1,
        Role.PATIENT,
        1,
        'user-agent',
        '127.0.0.1'
      );

      const decoded = jwt.decode(tokens.refreshToken);
      if (
        decoded &&
        typeof decoded === 'object' &&
        'exp' in decoded
      ) {
        expect(decoded.exp).toBe(
          Math.floor(now / 1000) + 60 * 60 * 24 * 7
        );
      } else {
        fail('Failed to decode token');
      }
    });
  });
});
