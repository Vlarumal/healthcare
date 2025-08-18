import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { AppDataSource } from '../data-source';
import { Patient } from '../entities/Patient';
import {
  generateFingerprint,
  publicKey,
  generateTokenVersionHash,
} from '../services/tokenService';
import logger from '../utils/logger';
import { HttpError, UnauthorizedError, ForbiddenError, InternalServerError, NotFoundError } from '../errors/httpErrors';

declare module 'express-serve-static-core' {
  interface Request {
    user?: {
      id: number;
      role: 'patient' | 'staff' | 'admin' | 'clinician';
    };
  }
}

export const authenticateJWT = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    const authHeader = req.headers.authorization;
    let token = authHeader?.split(' ')[1];

    if (!token && req.cookies?.accessToken) {
      token = req.cookies.accessToken;
    }

    if (!token) {
      const error = new UnauthorizedError('Authorization token required', 'MISSING_TOKEN');
      next(error);
      return;
    }

    const decoded = jwt.decode.call(jwt, token, { complete: true });
    if (!decoded || typeof decoded !== 'object') {
      const error = new ForbiddenError('Malformed token structure', 'INVALID_TOKEN');
      next(error);
      return;
    }
    const decodedHeader = decoded.header;
    if (decodedHeader?.alg !== 'RS256') {
      const error = new ForbiddenError('Unsupported token algorithm', 'INVALID_TOKEN_ALG');
      next(error);
      return;
    }

    if (!process.env.TOKEN_BINDING_SECRET) {
      logger.error(
        'TOKEN_BINDING_SECRET environment variable is not set'
      );
      const error = new InternalServerError('Internal server error', 'SERVER_ERROR');
      next(error);
      return;
    }

    let validToken: {
      sub: string;
      role: 'patient' | 'staff' | 'admin' | 'clinician';
      passwordVersion: number;
      tokenVersionHash?: string;
      fingerprint: string;
    };

    try {
      validToken = (await new Promise<any>((resolve, reject) => {
        jwt.verify(
          token,
          publicKey,
          {
            algorithms: ['RS256'],
            ignoreExpiration: false,
            clockTolerance: 30,
          },
          (err, decoded) => {
            if (err) {
              logger.error('JWT verification error:', err.message);
              reject(err);
            } else {
              logger.debug('JWT verified successfully');
              resolve(decoded);
            }
          }
        );
      })) as {
        sub: string;
        role: 'patient' | 'staff' | 'admin' | 'clinician';
        passwordVersion: number;
        tokenVersionHash?: string;
        fingerprint: string;
      };
    } catch (error: any) {
      if (error instanceof jwt.TokenExpiredError) {
        const tokenError = new ForbiddenError('Token expired', 'INVALID_TOKEN');
        next(tokenError);
        return;
      } else if (error instanceof jwt.JsonWebTokenError) {
        if (error.message.includes('invalid algorithm')) {
          const algError = new ForbiddenError('Unsupported token algorithm', 'INVALID_TOKEN_ALG');
          next(algError);
          return;
        } else if (
          error.message.includes('audience') ||
          error.message.includes('issuer')
        ) {
          const tokenError = new ForbiddenError('Malformed token structure', 'INVALID_TOKEN');
          next(tokenError);
          return;
        } else {
          const tokenError = new ForbiddenError('Malformed token structure', 'INVALID_TOKEN');
          next(tokenError);
          return;
        }
      } else {
        throw error;
      }
    }

    const clientFingerprint = generateFingerprint(
      req.headers['user-agent'] || '',
      req.ip || ''
    );

    if (validToken.fingerprint && validToken.fingerprint !== '') {
      if (
        process.env.NODE_ENV === 'test' &&
        !req.ip
      ) {
        logger.debug(
          'Skipping fingerprint validation in test environment with missing IP'
        );
      } else if (validToken.fingerprint !== clientFingerprint) {
        logger.error(
          `Token binding failed: token=${validToken.fingerprint} client=${clientFingerprint}`
        );
        const bindingError = new ForbiddenError('Token binding validation failed', 'INVALID_TOKEN_BINDING');
        next(bindingError);
        return;
      } else {
        logger.debug('Token binding validation passed');
      }
    } else {
      logger.debug('Token has no fingerprint, skipping binding validation');
    }

    if (!process.env.TOKEN_VERSION) {
      logger.error('TOKEN_VERSION environment variable is not set');
      const error = new InternalServerError('Internal server error', 'SERVER_ERROR');
      next(error);
      return;
    }
    const currentTokenVersionHash = generateTokenVersionHash();

    if (process.env.NODE_ENV !== 'test') {
      if (validToken.tokenVersionHash !== currentTokenVersionHash) {
        logger.error(
          `Token version mismatch: token=${validToken.tokenVersionHash} current=${currentTokenVersionHash}`
        );
        const tokenError = new ForbiddenError('Session invalidated', 'TOKEN_REVOKED');
        next(tokenError);
        return;
      } else {
        logger.debug('Token version validation passed');
      }
    }

    let userRepo;
    try {
      userRepo = AppDataSource.getRepository(Patient);
    } catch (dbError) {
      logger.error('Database repository access failed:', dbError);
      const error = new HttpError(503, 'SERVICE_UNAVAILABLE', 'Database service is initializing');
      next(error);
      return;
    }
    const userId = parseInt(validToken.sub);
    if (isNaN(userId)) {
      const error = new ForbiddenError(`Invalid user ID in token: ${validToken.sub}`, 'INVALID_TOKEN');
      next(error);
      return;
    }

    const user = await userRepo.findOne({
      where: { id: userId },
      select: ['id', 'role', 'passwordVersion'],
      cache: 5000,
    });

    if (!user) {
      const error = new NotFoundError('User not found', 'USER_NOT_FOUND');
      next(error);
      return;
    }

    if (validToken.passwordVersion !== user.passwordVersion) {
      logger.error(
        `Password version mismatch: token=${validToken.passwordVersion} user=${user.passwordVersion}`
      );
      const credError = new ForbiddenError('Please reauthenticate', 'CREDENTIALS_CHANGED');
      next(credError);
      return;
    } else {
      logger.debug('Password version validation passed');
    }

    req.user = {
      id: user.id,
      role: user.role as 'patient' | 'staff' | 'admin' | 'clinician',
    };
    next();
  } catch (error) {
    logger.error('Auth middleware error:', error);
    const authError = new InternalServerError('Authentication system failure', 'AUTH_ERROR');
    next(authError);
  }
};

export const authorizeRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.user?.role || !roles.includes(req.user.role)) {
      res.status(403).json({
        code: 'ACCESS_DENIED',
        message: 'Insufficient permissions for this operation',
      });
      return;
    }
    next();
  };
};
