import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { AppDataSource } from '../data-source';
import { Patient } from '../entities/Patient';
import { Role } from '../entities/Patient';
import { Token } from '../entities/Token';
import {
  UnauthorizedError,
  NotFoundError
} from '../errors/httpErrors';

import {
  ACCESS_TOKEN_EXPIRES_IN,
  REFRESH_TOKEN_EXPIRES_IN,
} from '../config';
import logger from '../utils/logger';

const TOKEN_ISSUER = process.env.TOKEN_ISSUER;
const TOKEN_AUDIENCE = process.env.TOKEN_AUDIENCE;

const privateKeyContent = fs.readFileSync(
  path.resolve(__dirname, '../../keys/private.pem'),
  'utf8'
);
if (privateKeyContent.length < 2048) {
  logger.warn('Private key size is less than 2048 bits, which is insecure');
  throw new Error('Insecure RSA key size');
}

export const privateKey = privateKeyContent;

logger.info(`Using refresh token expiry: ${REFRESH_TOKEN_EXPIRES_IN}`);
export const publicKey = fs.readFileSync(
  path.resolve(__dirname, '../../keys/public.pem'),
  'utf8'
);

export function generateFingerprint(userAgent: string, ip: string): string {
  const bindingSecret = process.env.TOKEN_BINDING_SECRET;
  if (!bindingSecret) {
    throw new Error('TOKEN_BINDING_SECRET environment variable is not set');
  }
  return crypto
    .createHmac('sha256', bindingSecret)
    .update(`${userAgent}${ip}`)
    .digest('hex');
}

/**
 * Validates token fingerprint by comparing with computed fingerprint
 * @param payload Decoded token payload
 * @param currentFingerprint Fingerprint computed from current request
 * @returns Boolean indicating validity
 */
export function validateTokenFingerprint(payload: jwt.JwtPayload, currentFingerprint: string): boolean {
  return payload.fingerprint === currentFingerprint;
}

export function generateTokenVersionHash(): string {
  if (!process.env.TOKEN_VERSION) {
    throw new Error('TOKEN_VERSION environment variable is not set');
  }
  return crypto
    .createHmac('sha256', process.env.TOKEN_VERSION)
    .update('v1')
    .digest('hex');
}
/**
 * Generates JWT tokens for authentication
 * @param userId - User ID
 * @param role - User role
 * @param passwordVersion - Password version for invalidation
 * @returns Object containing accessToken and refreshToken
 */
export const generateTokens = (
  userId: number,
  role: Role,
  passwordVersion: number,
  userAgent: string,
  clientIp: string
) => {
  const tokenVersionHash = generateTokenVersionHash();

  const fingerprint = generateFingerprint(userAgent, clientIp);

  const accessToken = jwt.sign(
    {
      sub: userId.toString(),
      role,
      passwordVersion,
      tokenVersionHash,
      fingerprint,
      iss: TOKEN_ISSUER,
      aud: TOKEN_AUDIENCE
    },
    privateKey,
    {
      expiresIn: ACCESS_TOKEN_EXPIRES_IN,
      algorithm: 'RS256'
    } as jwt.SignOptions
  );

  const tokenId = generateTokenId();
  const refreshToken = jwt.sign(
    {
      jti: tokenId,
      userId,
      tokenVersion: process.env.TOKEN_VERSION,
      fingerprint,
      tokenVersionHash,
      iss: TOKEN_ISSUER,
      aud: TOKEN_AUDIENCE
    },
    privateKey,
    {
      expiresIn: REFRESH_TOKEN_EXPIRES_IN,
      algorithm: 'RS256'
    } as jwt.SignOptions
  );

  return { accessToken, refreshToken };
};

/**
 * Stores refresh token in database using Token entity
 * @param userId - User ID
 * @param tokenId - JWT ID from refresh token
 * @param expiresAt - Token expiration timestamp in seconds
 */
export const storeRefreshToken = async (
  userId: number,
  tokenId: string,
  expiresAt: number,
  entityManager = AppDataSource.manager
) => {
  const tokenRepo = entityManager.getRepository(Token);
  const patientRepo = entityManager.getRepository(Patient);
  
  const user = await patientRepo.findOneBy({ id: userId });
  if (!user) {
    throw new NotFoundError('User not found');
  }

  const token = new Token();
  token.token = tokenId;
  token.type = 'refresh';
  token.expiresAt = new Date(expiresAt);
  token.patient = user;
  
  await tokenRepo.save(token);
};

/**
 * Verifies access token and returns payload
 * @param token - JWT access token
 * @param currentFingerprint - Fingerprint computed from current request for token binding
 * @returns Decoded token payload
 */
export const verifyAccessToken = (token: string, currentFingerprint: string) => {
  try {
    const payload = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      ignoreExpiration: false,
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE
    }) as jwt.JwtPayload;

    if (payload.fingerprint) {
      if (!currentFingerprint) {
        throw new UnauthorizedError('Token fingerprint validation requires current fingerprint');
      }
      const isValidFingerprint = validateTokenFingerprint(
        payload,
        currentFingerprint
      );
      if (!isValidFingerprint) {
        throw new UnauthorizedError('Token fingerprint does not match');
      }
    }

    const expectedTokenVersionHash = generateTokenVersionHash();
    if (payload.tokenVersionHash !== expectedTokenVersionHash) {
      throw new UnauthorizedError('Token version is invalid');
    }

    return payload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedError('Token expired');
    } else if (error instanceof jwt.NotBeforeError) {
      throw new UnauthorizedError('Token not yet active');
    } else if (error instanceof jwt.JsonWebTokenError || (error && typeof error === 'object' && 'name' in error && error.name === 'JsonWebTokenError')) {
      const message = (error as any).message || '';
      if (message.includes('audience') || message.includes('jwt audience invalid')) {
        throw new UnauthorizedError('Invalid token audience');
      } else if (message.includes('issuer')) {
        throw new UnauthorizedError('Invalid token issuer');
      } else {
        throw new UnauthorizedError('Invalid token signature');
      }
    } else if (error instanceof UnauthorizedError) {
      throw error;
    } else {
      throw new UnauthorizedError('Invalid access token');
    }
  }
};

/**
 * Verifies refresh token and checks database validity
 * @param token - JWT refresh token
 * @param currentFingerprint - Fingerprint computed from current request for token binding
 * @returns Decoded token payload
 */
export const verifyRefreshToken = async (token: string, currentFingerprint?: string) => {
  try {
    const payload = await new Promise<jwt.JwtPayload>((resolve, reject) => {
      jwt.verify(token, publicKey, {
        algorithms: ['RS256'],
        ignoreExpiration: false,
        issuer: TOKEN_ISSUER,
        audience: TOKEN_AUDIENCE
      }, (err, decoded) => {
        if (err) reject(err);
        else resolve(decoded as jwt.JwtPayload);
      });
    });
    
    if (payload.fingerprint && currentFingerprint) {
      const isValidFingerprint = validateTokenFingerprint(
        payload,
        currentFingerprint
      );
      if (!isValidFingerprint) {
        throw new UnauthorizedError('Token fingerprint does not match');
      }
    } else if (payload.fingerprint && !currentFingerprint) {
      throw new UnauthorizedError('Token fingerprint validation requires current fingerprint');
    }
    
    const expectedTokenVersionHash = generateTokenVersionHash();
    if (payload.tokenVersionHash !== expectedTokenVersionHash) {
      throw new UnauthorizedError('Refresh token version is invalid');
    }
    
    const tokenRepo = AppDataSource.getRepository(Token);
    const tokenRecord = await tokenRepo.findOneBy({ token: payload.jti });
    
    if (!tokenRecord || tokenRecord.revoked) {
      throw new UnauthorizedError('Refresh token revoked');
    }
    
    return payload;
  } catch (error) {
    if (error instanceof UnauthorizedError) {
      throw error;
    }
    throw new UnauthorizedError('Invalid refresh token');
  }
};

/**
 * Rotates refresh token using Token entity
 * @param userId - User ID
 * @param oldTokenId - JWT ID of previous refresh token
 * @returns New refresh token
 */
export const rotateRefreshToken = async (
  userId: number,
  oldTokenId: string | undefined,
  userAgent: string,
  clientIp: string
) => {
  const fingerprint = generateFingerprint(userAgent, clientIp);

  const newRefreshToken = jwt.sign(
    {
      jti: generateTokenId(),
      userId,
      tokenVersion: process.env.TOKEN_VERSION,
      fingerprint,
      tokenVersionHash: generateTokenVersionHash(),
      iss: process.env.TOKEN_ISSUER || 'healthcare-system',
      aud: process.env.TOKEN_AUDIENCE || 'healthcare-audience'
    },
    privateKey,
    {
      expiresIn: REFRESH_TOKEN_EXPIRES_IN,
      algorithm: 'RS256'
    } as jwt.SignOptions
  );

  const decoded = jwt.decode(newRefreshToken) as jwt.JwtPayload;

  try {
    await AppDataSource.transaction(async (transactionalEntityManager) => {
      await storeRefreshToken(userId, decoded.jti!, decoded.exp! * 1000, transactionalEntityManager);
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    logger.error(`Token rotation transaction failed: ${errorMessage}`);
    logger.warn('Continuing token rotation despite transaction error');
  }

  if (oldTokenId) {
    try {
      const revokeResult = await revokeToken(userId, oldTokenId);
      if (!revokeResult) {
        logger.warn(`Failed to revoke old token during rotation: ${oldTokenId}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.warn(`Failed to revoke old token during rotation: ${oldTokenId} - ${errorMessage}`);
    }
  }
  return newRefreshToken;
};

/**
 * Revokes a refresh token using Token entity
 * @param userId - User ID
 * @param tokenId - JWT ID to revoke
 */
export const revokeToken = async (userId: number, tokenId: string, entityManager = AppDataSource.manager) => {
  if (!tokenId) {
    logger.warn('Attempted to revoke token with undefined tokenId');
    return false;
  }
  
  if (!entityManager) {
    logger.error('EntityManager is undefined in revokeToken');
    throw new Error('Database connection error');
  }

  const tokenRepo = entityManager.getRepository(Token);
  
  try {
    const token = await tokenRepo.findOne({
      where: {
        token: tokenId,
        revoked: false
      },
      relations: ['patient']
    });

    if (!token) {
      logger.warn(`Token not found: ${tokenId}`);
      return false;
    }

    if (token.patient.id !== userId) {
      logger.warn(`Token does not belong to user: ${tokenId}`);
      return false;
    }

    token.revoked = true;
    await tokenRepo.save(token);
    logger.info(`Successfully revoked token: ${tokenId}`);
    return true;
  } catch (error) {
    logger.error(`Failed to revoke token: ${tokenId}`, { error });
    return false;
  }
};

/**
 * Generates unique token ID using crypto module
 * @returns Random token ID string
 */
const generateTokenId = () => {
  return crypto.randomBytes(32).toString('hex');
};

/**
 * Revokes all active refresh tokens for a user
 * @param userId - User ID
 * @param entityManager - Optional entity manager
 */
export const revokeAllTokensForUser = async (userId: number, entityManager = AppDataSource.manager) => {
  const maxRetries = 3;
  let retryCount = 0;
  
  while (retryCount < maxRetries) {
    try {
      return await entityManager.transaction(async (transactionalEntityManager) => {
        const tokenRepo = transactionalEntityManager.getRepository(Token);
        const updateResult = await tokenRepo.createQueryBuilder()
          .update(Token)
          .set({ revoked: true })
          .where("patient.id = :userId AND revoked = :revoked", {
            userId,
            revoked: false
          })
          .andWhere("id IN (SELECT id FROM token WHERE patient.id = :userId AND revoked = false FOR UPDATE SKIP LOCKED)")
          .execute();

        logger.info(`Revoked ${updateResult.affected} tokens for user ${userId}`);
        return updateResult.affected ?? 0;
      });
    } catch (error: unknown) {
      if (error instanceof Error) {
        if (error.message.includes('deadlock') || (error as any).code === '40001') {
          retryCount++;
          logger.warn(`Concurrent token revocation detected, retrying (${retryCount}/${maxRetries})`);
          await new Promise(resolve => setTimeout(resolve, 50 * retryCount));
        } else {
          logger.error(`Failed to revoke tokens for user ${userId}`, { error });
          return 0;
        }
      } else {
        logger.error(`Unknown error type during token revocation: ${error}`);
        return 0;
      }
    }
  }
  
  logger.error(`Failed to revoke tokens for user ${userId} after ${maxRetries} attempts`);
  return 0;
};
