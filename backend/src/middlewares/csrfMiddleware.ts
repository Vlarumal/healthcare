import dotenv from 'dotenv';
dotenv.config();

import { Request } from 'express';
import { doubleCsrf } from 'csrf-csrf';
import logger from '../utils/logger';
import { cookieDomain, CSRF_SECRET } from '../config';
import { InternalServerError } from '../errors/httpErrors';

const getSessionIdentifier = (_req: Request): string => '';

export const createCsrfMiddleware = () => {
  if (!process.env.CSRF_SECRET) {
    throw new Error('CSRF secret not configured');
  }

  if (!process.env.CSRF_SECRET || process.env.CSRF_SECRET === '') {
    logger.error(
      'CSRF_SECRET environment variable is not set or is empty'
    );
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR'
    );
  }

  if (
    process.env.NODE_ENV === 'production' &&
    !process.env.COOKIE_DOMAIN
  ) {
    logger.error('COOKIE_DOMAIN environment variable is not set');
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR'
    );
  }

  let sameSite: 'lax' | 'strict' | 'none' | boolean | undefined;
  if (process.env.COOKIE_SAMESITE) {
    const validValues = ['lax', 'strict', 'none', 'true', 'false'];
    if (validValues.includes(process.env.COOKIE_SAMESITE)) {
      if (process.env.COOKIE_SAMESITE === 'true') {
        sameSite = true;
      } else if (process.env.COOKIE_SAMESITE === 'false') {
        sameSite = false;
      } else {
        sameSite = process.env.COOKIE_SAMESITE as
          | 'lax'
          | 'strict'
          | 'none';
      }
    } else {
      logger.warn(
        `COOKIE_SAMESITE value: ${process.env.COOKIE_SAMESITE}. Using 'lax' in production, 'strict' in development.`
      );
    }
  }

  if (sameSite === undefined) {
    sameSite =
      process.env.NODE_ENV === 'production' ? 'lax' : 'strict';
  }

  let httpOnly = true;
  if (process.env.COOKIE_HTTPONLY !== undefined) {
    httpOnly = process.env.COOKIE_HTTPONLY.toLowerCase() === 'true';
  } else {
    logger.warn(
      'COOKIE_HTTPONLY not set, using default httpOnly=true'
    );
  }

  const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier,
    cookieName: 'csrfToken',
    cookieOptions: {
      secure:
        process.env.NODE_ENV === 'production' &&
        process.env.PROXY_SECURE === 'true',
      sameSite,
      httpOnly,
      ...(process.env.NODE_ENV === 'production' && {
        domain: cookieDomain || '.onrender.com',
      }),
      maxAge: 3600000, // 1 hour expiration
    },
    size: 64,
    ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
    errorConfig: {
      code: 'CSRF_TOKEN_MISSING_OR_INVALID',
      message: 'CSRF token missing or invalid',
    },
  });

  return { doubleCsrfProtection, generateCsrfToken };
};
