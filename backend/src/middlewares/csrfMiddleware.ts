import dotenv from 'dotenv';
dotenv.config();

import { Request } from 'express';
import { doubleCsrf } from 'csrf-csrf';
import logger from '../utils/logger';
import { cookieDomain, CSRF_SECRET } from '../config';
import { InternalServerError } from '../errors/httpErrors';

const getSessionIdentifier = (req: Request): string => {
  if (req.cookies && req.cookies.session) {
    return req.cookies.session;
  }

  if (req.ip) {
    return req.ip;
  }

  const forwarded = req.headers['x-forwarded-for'];
  if (Array.isArray(forwarded) && forwarded.length > 0) {
    // Return the first IP in the array (client IP)
    return forwarded[0].split(',')[0].trim();
  }
  
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string' && realIp.length > 0) {
    return realIp.trim();
  }

  const cfConnectingIp = req.headers['cf-connecting-ip'];
  if (typeof cfConnectingIp === 'string' && cfConnectingIp.length > 0) {
    return cfConnectingIp.trim();
  }

  return 'default-session';
};

export const createCsrfMiddleware = () => {
  if (!process.env.CSRF_SECRET) {
    throw new Error('CSRF secret not configured');
  }

  if (process.env.NODE_ENV === 'production' && !cookieDomain) {
    logger.error('COOKIE_DOMAIN environment variable is not set');
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR'
    );
  }
  
  if (!CSRF_SECRET) {
    logger.error('CSRF_SECRET environment variable is not set');
    throw new InternalServerError(
      'Internal server error',
      'SERVER_ERROR'
    );
  }

  const { doubleCsrfProtection, generateCsrfToken } = doubleCsrf({
    getSecret: () => CSRF_SECRET,
    getSessionIdentifier,
    cookieName: 'csrfToken',
    cookieOptions: {
      secure: process.env.NODE_ENV === 'production',
      // secure: isProduction,
      sameSite: 'strict', // Always use strict for better security
      // sameSite: isProduction ? 'strict' : 'lax', // Adjust for cross-site in production ('none')
      httpOnly: true,
      ...((cookieDomain && process.env.NODE_ENV === 'production') && { domain: cookieDomain }),
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

export {
  getSessionIdentifier,
};
