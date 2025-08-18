import request from 'supertest';
import { NextFunction } from 'express';
import { app } from '../../index';
import errorHandler from '../errorHandler';
import {
  ConsentNotFoundError,
  ConsentExpiredError,
  InvalidConsentStatusError,
} from '../../errors/consentErrors';
import { PatientNotFoundError } from '../../errors/patientErrors';
import {
  HttpError,
  NotFoundError,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  InternalServerError,
  CsrfValidationError,
  InvalidTokenError,
} from '../../errors/httpErrors';
import {
  UserNotFoundError,
  TokenRotationError,
} from '../../errors/authErrors';
import {
  DatabaseConnectionError,
  DatabaseQueryError,
  RecordNotFoundError,
  DuplicateRecordError,
} from '../../errors/databaseErrors';
import { ValidationError } from '../../errors/validationError';

interface ErrorWithStatus extends Error {
  status?: number;
  code?: string;
}

describe('errorHandler middleware', () => {
  app.get('/error', (_req, _res, next: NextFunction) => {
    const error = new Error('Test error') as ErrorWithStatus;
    error.status = 400;
    next(error);
  });

  app.get('/unhandled', () => {
    throw new Error('Unhandled error');
  });

  app.get('/non-error', () => {
    throw 'Plain string error';
  });

  app.get('/generic-error', (_, __, next) => {
    const error = new Error('An unexpected error occurred');
    next(error);
  });

  app.get('/custom-error', (_, __, next) => {
    const error = new HttpError(
      400,
      'VALIDATION_ERROR',
      'Custom error'
    );
    next(error);
  });

  app.get('/consent-not-found', (_, __, next) => {
    const error = new ConsentNotFoundError(123);
    next(error);
  });

  app.get('/consent-expired', (_, __, next) => {
    const error = new ConsentExpiredError(456);
    next(error);
  });

  app.get('/invalid-consent-status', (_, __, next) => {
    const error = new InvalidConsentStatusError(789, 'pending');
    next(error);
  });

  app.get('/patient-not-found', (_, __, next) => {
    const error = new PatientNotFoundError();
    next(error);
  });

  app.get('/user-not-found', (_, __, next) => {
    const error = new UserNotFoundError();
    next(error);
  });

  app.get('/token-rotation-error', (_, __, next) => {
    const error = new TokenRotationError('Token rotation failed');
    next(error);
  });

  app.get('/database-connection-error', (_, __, next) => {
    const error = new DatabaseConnectionError(
      'Database connection failed'
    );
    next(error);
  });

  app.get('/database-query-error', (_, __, next) => {
    const error = new DatabaseQueryError('Database query failed');
    next(error);
  });

  app.get('/record-not-found-error', (_, __, next) => {
    const error = new RecordNotFoundError('Patient', '123');
    next(error);
  });

  app.get('/not-found-error', (_, __, next) => {
    const error = new NotFoundError('Generic not found error');
    next(error);
  });

  app.get('/generic-not-found-error', (_, __, next) => {
    const error = new NotFoundError('Generic not found');
    next(error);
  });

  app.get('/validation-error', (_, __, next) => {
    const error = new ValidationError([
      { field: 'password', message: 'Too weak' },
    ]);
    next(error);
  });

  app.get('/validation-error-with-id', (_, __, next) => {
    const error = new ValidationError([
      { field: 'email', message: 'Invalid email' },
    ]);
    (error as any).id = 'validation-error-id-123';
    next(error);
  });

  app.get('/validation-error-empty', (_, __, next) => {
    const error = new ValidationError([]);
    next(error);
  });

  app.get('/http-error-empty-message', (_, __, next) => {
    const error = new HttpError(400, 'VALIDATION_ERROR', '');
    next(error);
  });

  app.get('/duplicate-email-error', (_, __, next) => {
    const error = new DuplicateRecordError(
      'email',
      'test@example.com'
    );
    next(error);
  });

  app.get('/http-error-with-details', (_, __, next) => {
    const error = new HttpError(
      400,
      'VALIDATION_ERROR',
      'Custom error',
      { field: 'email', issue: 'Invalid format' }
    );
    next(error);
  });

  app.get('/csrf-error', (_, __, next) => {
    const error = new Error('CSRF token missing or invalid') as any;
    error.code = 'EBADCSRFTOKEN';
    next(error);
  });

  app.get('/csrf-error-missing', (_, __, next) => {
    const error = new Error('CSRF token missing') as any;
    error.code = 'CSRF_TOKEN_MISSING_OR_INVALID';
    next(error);
  });

  app.get('/non-error-with-id', (_, __, next) => {
    const error = { message: 'Non-error with id', id: 'test-id-123' };
    next(error);
  });

  app.get('/null-error', (_req, _res, next) => {
    next(new Error('Non-error object thrown: null'));
  });

  app.get('/undefined-error', (_req, _res, next) => {
    next(new Error('Unknown error occurred'));
  });

  app.get('/consent-not-found-fallback', (_, __, next) => {
    const error = new Error('Consent with id 123 not found') as any;
    error.constructor = { name: 'ConsentNotFoundError' };
    error.consentId = 123;
    next(error);
  });

  app.get('/localized-error', (_, __, next) => {
    const error = new ConsentNotFoundError(123);
    next(error);
  });

  app.get('/localized-generic-error', (_, __, next) => {
    const error = new Error('Generic error message') as any;
    error.status = 400;
    next(error);
  });

  app.get('/bad-request-error', (_, __, next) => {
    const error = new BadRequestError('Bad request error');
    next(error);
  });

  app.get('/unauthorized-error', (_, __, next) => {
    const error = new UnauthorizedError('Unauthorized error');
    next(error);
  });

  app.get('/forbidden-error', (_, __, next) => {
    const error = new ForbiddenError('Forbidden error');
    next(error);
  });

  app.get('/internal-server-error', (_, __, next) => {
    const error = new InternalServerError('Internal server error');
    next(error);
  });

  app.get('/invalid-token-error', (_, __, next) => {
    const error = new InvalidTokenError('Invalid token error');
    next(error);
  });

  app.get('/network-error-notfound', (_, __, next) => {
    const error = new Error(
      'getaddrinfo ENOTFOUND example.com'
    ) as any;
    error.code = 'ENOTFOUND';
    next(error);
  });

  app.get('/network-error-connrefused', (_, __, next) => {
    const error = new Error(
      'connect ECONNREFUSED 127.0.0.1:8080'
    ) as any;
    error.code = 'ECONNREFUSED';
    next(error);
  });

  app.get('/network-error-timedout', (_, __, next) => {
    const error = new Error(
      'connect ETIMEDOUT 127.0.0.1:8080'
    ) as any;
    error.code = 'ETIMEDOUT';
    next(error);
  });

  app.get('/csrf-validation-error', (_, __, next) => {
    const error = new CsrfValidationError('CSRF validation failed');
    next(error);
  });

  app.use(errorHandler);

  it('includes security headers in error responses', async () => {
    const response = await request(app).get('/error');
    expect(response.headers['x-content-type-options']).toBe(
      'nosniff'
    );
    expect(response.headers['x-request-id']).toBeDefined();
  });

  it('includes stack trace in development environment for ValidationError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/validation-error');
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details: {
        errors: [{ field: 'password', message: 'Too weak' }],
      },
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for HttpError with details', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/custom-error');
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Custom error',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for ConsentNotFoundError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/consent-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'CONSENT_NOT_FOUND',
      message: 'Consent with id 123 not found',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for ConsentExpiredError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/consent-expired');
    expect(response.status).toBe(410);
    expect(response.body.error).toEqual({
      status: 410,
      code: 'CONSENT_EXPIRED',
      message: 'Consent with id 456 has expired',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for InvalidConsentStatusError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get(
      '/invalid-consent-status'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'INVALID_CONSENT_STATUS',
      message: 'Consent with id 789 has invalid status: pending',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for PatientNotFoundError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/patient-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Patient not found',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for UserNotFoundError', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/user-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'USER_NOT_FOUND',
      message: 'User not found',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('includes stack trace in development environment for generic error', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/generic-error');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'An unexpected error occurred',
      stack: expect.any(String),
    });
    process.env.NODE_ENV = 'test';
  });

  it('handles custom AppError with code', async () => {
    const response = await request(app).get('/custom-error');
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Custom error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles generic NotFoundError with 404 status', async () => {
    const response = await request(app).get('/not-found-error');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'NOT_FOUND',
      message: 'Generic not found error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles UserNotFoundError with 404 status', async () => {
    const response = await request(app).get('/user-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'USER_NOT_FOUND',
      message: 'User not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles UserNotFoundError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/user-not-found')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'USER_NOT_FOUND',
      message: 'Користувача не знайдено',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles UserNotFoundError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/user-not-found')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'USER_NOT_FOUND',
      message: 'Vartotojas nerastas',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles UserNotFoundError localization with Russian language', async () => {
    const response = await request(app)
      .get('/user-not-found')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'USER_NOT_FOUND',
      message: 'Пользователь не найден',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles error localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/localized-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'CONSENT_NOT_FOUND',
      message: 'Згоду з id 123 не знайдено',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles error localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/localized-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'CONSENT_NOT_FOUND',
      message: 'Sutikimas su ID 123 nerastas',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles error localization with Russian language', async () => {
    const response = await request(app)
      .get('/localized-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'CONSENT_NOT_FOUND',
      message: 'Согласие с ID 123 не найдено',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles undefined errors', async () => {
    const response = await request(app).get('/undefined-error');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'Unknown error occurred',
    });
  });

  it('handles non-Error objects with id property', async () => {
    const response = await request(app).get('/non-error-with-id');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'Non-error object thrown: [object Object]',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles errors with status code', async () => {
    const response = await request(app).get('/error');
    expect(response.status).toBe(400);
    expect(response.body).toEqual({
      error: {
        status: 400,
        message: 'Test error',
        ...(process.env.NODE_ENV === 'development' && {
          stack: expect.any(String),
        }),
      },
    });
  });

  it('handles non-Error object throws', async () => {
    const response = await request(app).get('/non-error');
    expect(response.status).toBe(500);
    expect(response.body.error.message).toBe(
      'Non-error object thrown: Plain string error'
    );
  });

  it('handles uncaught errors with 500 status', async () => {
    const response = await request(app).get('/unhandled');
    expect(response.status).toBe(500);
    expect(response.body.error.message).toBe('Unhandled error');
  });

  it('includes stack trace in development', async () => {
    process.env.NODE_ENV = 'development';
    const response = await request(app).get('/error');
    expect(response.body.error.stack).toBeDefined();
    process.env.NODE_ENV = 'test';
  });

  it('validates error response schema', async () => {
    const response = await request(app).get('/error');
    expect(response.body).toEqual({
      error: {
        status: expect.any(Number),
        message: expect.any(String),
        ...(process.env.NODE_ENV === 'development' && {
          stack: expect.any(String),
        }),
      },
    });
  });

  it('excludes stack trace in production', async () => {
    process.env.NODE_ENV = 'production';
    const response = await request(app).get('/error');
    expect(response.body.error.stack).toBeUndefined();
    process.env.NODE_ENV = 'test';
  });

  it('handles ConsentNotFoundError with 404 status', async () => {
    const response = await request(app).get('/consent-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'CONSENT_NOT_FOUND',
      message: 'Consent with id 123 not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ConsentExpiredError with 410 status', async () => {
    const response = await request(app).get('/consent-expired');
    expect(response.status).toBe(410);
    expect(response.body.error).toEqual({
      status: 410,
      code: 'CONSENT_EXPIRED',
      message: 'Consent with id 456 has expired',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ConsentExpiredError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/consent-expired')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(410);
    expect(response.body.error).toEqual({
      status: 410,
      code: 'CONSENT_EXPIRED',
      message: 'Згода з id 456 закінчилася',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ConsentExpiredError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/consent-expired')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(410);
    expect(response.body.error).toEqual({
      status: 410,
      code: 'CONSENT_EXPIRED',
      message: 'Sutikimas su ID 456 pasibaigė',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ConsentExpiredError localization with Russian language', async () => {
    const response = await request(app)
      .get('/consent-expired')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(410);
    expect(response.body.error).toEqual({
      status: 410,
      code: 'CONSENT_EXPIRED',
      message: 'Согласие с ID 456 истекло',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InvalidConsentStatusError with 400 status', async () => {
    const response = await request(app).get(
      '/invalid-consent-status'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'INVALID_CONSENT_STATUS',
      message: 'Consent with id 789 has invalid status: pending',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InvalidConsentStatusError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/invalid-consent-status')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'INVALID_CONSENT_STATUS',
      message: 'Згода з id 789 має недійсний статус: pending',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InvalidConsentStatusError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/invalid-consent-status')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'INVALID_CONSENT_STATUS',
      message: 'Sutikimas su ID 789 turi neteisingą būseną: pending',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InvalidConsentStatusError localization with Russian language', async () => {
    const response = await request(app)
      .get('/invalid-consent-status')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'INVALID_CONSENT_STATUS',
      message: 'Согласие с ID 789 имеет недопустимый статус: pending',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles PatientNotFoundError with 404 status', async () => {
    const response = await request(app).get('/patient-not-found');
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Patient not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles PatientNotFoundError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/patient-not-found')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Пацієнта не знайдено',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles PatientNotFoundError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/patient-not-found')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Pacientas nerastas',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles PatientNotFoundError localization with Russian language', async () => {
    const response = await request(app)
      .get('/patient-not-found')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'PATIENT_NOT_FOUND',
      message: 'Пациент не найден',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ValidationError with 400 status', async () => {
    const response = await request(app).get('/validation-error');
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details: {
        errors: [{ field: 'password', message: 'Too weak' }],
      },
    });
  });

  it('handles ValidationError with id correctly', async () => {
    const response = await request(app).get(
      '/validation-error-with-id'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details: {
        errors: [{ field: 'email', message: 'Invalid email' }],
      },
    });
  });

  it('handles CSRF token errors with 403 status', async () => {
    const response = await request(app).get('/csrf-error');
    expect(response.status).toBe(403);
    expect(response.headers['x-content-type-options']).toBe(
      'nosniff'
    );
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.body.error).toEqual({
      status: 403,
      code: 'EBADCSRFTOKEN',
      message: 'CSRF token missing or invalid',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles CSRF token errors with CSRF_TOKEN_MISSING_OR_INVALID code', async () => {
    const response = await request(app).get('/csrf-error-missing');
    expect(response.status).toBe(403);
    expect(response.headers['x-content-type-options']).toBe(
      'nosniff'
    );
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.body.error).toEqual({
      status: 403,
      code: 'CSRF_TOKEN_MISSING_OR_INVALID',
      message: 'CSRF token missing or invalid',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ValidationError with empty details', async () => {
    const response = await request(app).get(
      '/validation-error-empty'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
    });
  });

  it('handles HttpError with empty message', async () => {
    const response = await request(app).get(
      '/http-error-empty-message'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'An error occurred',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles HttpError with details', async () => {
    const response = await request(app).get(
      '/http-error-with-details'
    );
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'VALIDATION_ERROR',
      message: 'Custom error',
      details: { field: 'email', issue: 'Invalid format' },
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DUPLICATE_EMAIL error with 409 status', async () => {
    const response = await request(app).get('/duplicate-email-error');
    expect(response.status).toBe(409);
    expect(response.headers['x-content-type-options']).toBe(
      'nosniff'
    );
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.body.error).toEqual({
      status: 409,
      code: 'DUPLICATE_EMAIL',
      message: 'Email already exists',
      details: {
        errors: [
          { field: 'email', message: 'Email is already in use' },
        ],
      },
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DUPLICATE_EMAIL error with localization in Ukrainian', async () => {
    const response = await request(app)
      .get('/duplicate-email-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(409);
    expect(response.body.error).toEqual({
      status: 409,
      code: 'DUPLICATE_EMAIL',
      message: 'Email already exists',
      details: {
        errors: [
          { field: 'email', message: 'Email is already in use' },
        ],
      },
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DUPLICATE_EMAIL error with localization in Lithuanian', async () => {
    const response = await request(app)
      .get('/duplicate-email-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(409);
    expect(response.body.error).toEqual({
      status: 409,
      code: 'DUPLICATE_EMAIL',
      message: 'Email already exists',
      details: {
        errors: [
          { field: 'email', message: 'Email is already in use' },
        ],
      },
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DUPLICATE_EMAIL error with localization in Russian', async () => {
    const response = await request(app)
      .get('/duplicate-email-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(409);
    expect(response.body.error).toEqual({
      status: 409,
      code: 'DUPLICATE_EMAIL',
      message: 'Email already exists',
      details: {
        errors: [
          { field: 'email', message: 'Email is already in use' },
        ],
      },
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles generic NotFoundError', async () => {
    const response = await request(app).get(
      '/generic-not-found-error'
    );
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'NOT_FOUND',
      message: 'Generic not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles error localization with Ukrainian language for non-Consent errors', async () => {
    const response = await request(app)
      .get('/localized-generic-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      message: 'Generic error message',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles null errors', async () => {
    const response = await request(app).get('/null-error');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'Non-error object thrown: null',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ConsentNotFoundError in fallback error handling', async () => {
    const response = await request(app).get(
      '/consent-not-found-fallback'
    );
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'Consent with id 123 not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles fallback for completely undefined errors', () => {
    const mockReq = { headers: {} } as any;
    const mockRes = {
      set: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    } as any;
    const mockNext = jest.fn();

    const errorHandler = require('../errorHandler').default;

    errorHandler(undefined, mockReq, mockRes, mockNext);

    expect(mockRes.set).toHaveBeenCalledWith({
      'x-content-type-options': 'nosniff',
      'x-request-id': expect.any(String),
    });
    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: {
        status: 500,
        message: 'Unknown error occurred',
      },
    });
  });

  it('handles undefined/null errors by creating a new Error object', () => {
    const mockReq = { headers: {} } as any;
    const mockRes = {
      set: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    } as any;
    const mockNext = jest.fn();

    errorHandler(null, mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: expect.objectContaining({
        status: 500,
        message: 'Non-error object thrown: null',
      }),
    });

    errorHandler(undefined, mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: expect.objectContaining({
        status: 500,
        message: 'Unknown error occurred',
      }),
    });
  });

  it('validates NotFoundError response structure', () => {
    const mockReq = { headers: {} } as any;
    const mockRes = {
      set: jest.fn().mockReturnThis(),
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    } as any;
    const mockNext = jest.fn();

    const notFoundError = new NotFoundError('User not found');

    notFoundError.details = {
      userId: '123',
      resource: 'User',
    };

    errorHandler(notFoundError, mockReq, mockRes, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(404);
    expect(mockRes.json).toHaveBeenCalledWith({
      error: expect.objectContaining({
        status: 404,
        message: 'User not found',
        code: 'NOT_FOUND',
        details: {
          userId: '123',
          resource: 'User',
        },
      }),
    });
  });
  it('handles TokenRotationError with 401 status', async () => {
    const response = await request(app).get('/token-rotation-error');
    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'TOKEN_ROTATION_ERROR',
      message: 'Token rotation failed',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles TokenRotationError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/token-rotation-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'TOKEN_ROTATION_ERROR',
      message: 'Помилка обертання токена',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles TokenRotationError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/token-rotation-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'TOKEN_ROTATION_ERROR',
      message: 'Nepavyko apversti žetono',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles TokenRotationError localization with Russian language', async () => {
    const response = await request(app)
      .get('/token-rotation-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'TOKEN_ROTATION_ERROR',
      message: 'Ошибка смены токена',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles network error with ENOTFOUND code', async () => {
    const response = await request(app).get(
      '/network-error-notfound'
    );
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'getaddrinfo ENOTFOUND example.com',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles network error with ECONNREFUSED code', async () => {
    const response = await request(app).get(
      '/network-error-connrefused'
    );
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'connect ECONNREFUSED 127.0.0.1:8080',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles network error with ETIMEDOUT code', async () => {
    const response = await request(app).get(
      '/network-error-timedout'
    );
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      message: 'connect ETIMEDOUT 127.0.0.1:8080',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles BadRequestError with 400 status', async () => {
    const response = await request(app).get('/bad-request-error');
    expect(response.status).toBe(400);
    expect(response.body.error).toEqual({
      status: 400,
      code: 'BAD_REQUEST',
      message: 'Bad request error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles UnauthorizedError with 401 status', async () => {
    const response = await request(app).get('/unauthorized-error');
    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'UNAUTHORIZED',
      message: 'Unauthorized error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles ForbiddenError with 403 status', async () => {
    const response = await request(app).get('/forbidden-error');
    expect(response.status).toBe(403);
    expect(response.body.error).toEqual({
      status: 403,
      code: 'FORBIDDEN',
      message: 'Forbidden error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InternalServerError with 500 status', async () => {
    const response = await request(app).get('/internal-server-error');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'INTERNAL_SERVER_ERROR',
      message: 'Internal server error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles InvalidTokenError with 401 status', async () => {
    const response = await request(app).get('/invalid-token-error');
    expect(response.status).toBe(401);
    expect(response.body.error).toEqual({
      status: 401,
      code: 'INVALID_TOKEN',
      message: 'Invalid token error',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles CsrfValidationError with 403 status', async () => {
    const response = await request(app).get('/csrf-validation-error');
    expect(response.status).toBe(403);
    expect(response.body.error).toEqual({
      status: 403,
      code: 'CSRF_VALIDATION_FAILED',
      message: 'CSRF validation failed',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseConnectionError with 500 status', async () => {
    const response = await request(app).get(
      '/database-connection-error'
    );
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_CONNECTION_ERROR',
      message: 'Database connection failed',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseQueryError with 500 status', async () => {
    const response = await request(app).get('/database-query-error');
    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_QUERY_ERROR',
      message: 'Database query failed',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles RecordNotFoundError with 404 status', async () => {
    const response = await request(app).get(
      '/record-not-found-error'
    );
    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'RECORD_NOT_FOUND',
      message: 'Patient with identifier 123 not found',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseConnectionError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/database-connection-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_CONNECTION_ERROR',
      message: 'Помилка підключення до бази даних',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseQueryError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/database-query-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_QUERY_ERROR',
      message: 'Помилка запиту до бази даних',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles RecordNotFoundError localization with Ukrainian language', async () => {
    const response = await request(app)
      .get('/record-not-found-error')
      .set('Accept-Language', 'uk');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'RECORD_NOT_FOUND',
      message: 'Пацієнта з ідентифікатором 123 не знайдено',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseConnectionError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/database-connection-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_CONNECTION_ERROR',
      message: 'Duomenų bazės ryšio klaida',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseQueryError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/database-query-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_QUERY_ERROR',
      message: 'Duomenų bazės užklausos klaida',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles RecordNotFoundError localization with Lithuanian language', async () => {
    const response = await request(app)
      .get('/record-not-found-error')
      .set('Accept-Language', 'lt');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'RECORD_NOT_FOUND',
      message: 'Įrašas „Patient“ su identifikatoriumi 123 nerastas',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseConnectionError localization with Russian language', async () => {
    const response = await request(app)
      .get('/database-connection-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_CONNECTION_ERROR',
      message: 'Ошибка подключения к базе данных',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles DatabaseQueryError localization with Russian language', async () => {
    const response = await request(app)
      .get('/database-query-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(500);
    expect(response.body.error).toEqual({
      status: 500,
      code: 'DATABASE_QUERY_ERROR',
      message: 'Ошибка запроса к базе данных',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });

  it('handles RecordNotFoundError localization with Russian language', async () => {
    const response = await request(app)
      .get('/record-not-found-error')
      .set('Accept-Language', 'ru');

    expect(response.status).toBe(404);
    expect(response.body.error).toEqual({
      status: 404,
      code: 'RECORD_NOT_FOUND',
      message: 'Запись Patient с идентификатором 123 не найдена',
      ...(process.env.NODE_ENV === 'development' && {
        stack: expect.any(String),
      }),
    });
  });
});
