import { Request, Response, NextFunction, ErrorRequestHandler } from 'express';
import { localizeError, getLanguageFromRequest } from '../utils/localization';
import { v4 as uuidv4 } from 'uuid';
import { AccessDeniedError, HttpError } from '../errors/httpErrors';
import { LocalizedError } from '../errors/LocalizedError';
import { ValidationError } from '../errors/validationError';
import ErrorLogger from '../utils/errorLogger';

interface ErrorWithStatus extends Error {
  status?: number;
  code?: string;
}

const sendErrorResponse = (
  res: Response,
  status: number,
  error: {
    status?: number;
    code?: string;
    message: string;
    details?: any;
    stack?: string;
  },
  requestId: string
) => {
  res
    .set({
      'x-content-type-options': 'nosniff',
      'x-request-id': requestId
    })
    .status(status)
    .json({
      error: {
        status: error.status || status,
        code: error.code,
        message: error.message,
        ...(error.details && { details: error.details }),
        ...(process.env.NODE_ENV === 'development' && error.stack && { stack: error.stack })
      }
    });
};

const errorHandler: ErrorRequestHandler = (
  err: any,
  req: Request,
  res: Response,
  _next: NextFunction
) => {
  
  const lang = getLanguageFromRequest(req);
  
  if (err && (err.code === 'EBADCSRFTOKEN' || err.code === 'CSRF_TOKEN_MISSING_OR_INVALID')) {
    const status = 403;
    const message = 'CSRF token missing or invalid';
    const code = err.code || 'CSRF_TOKEN_MISSING_OR_INVALID';
    
    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message
    });

    sendErrorResponse(res, status, { status, code, message, stack: err.stack }, uuidv4());
    
    return;
  }
  
  if (err && (err.name === 'ValidationError' || err instanceof ValidationError)) {
    const status = 400;
    const message = 'Validation failed';
    const details = err.details || [];
    const code = err.code || 'VALIDATION_ERROR';

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message,
        ...(err?.id && { errorId: err.id })
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      details: details.length > 0 ? { errors: details } : undefined,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  if (err && (err.code === 'DUPLICATE_EMAIL' || err.code === 'DUPLICATE_RECORD' || err?.name === 'DuplicateRecordError')) {
    const status = 409;
    const message = err.message || 'Email already exists';
    const details = err.details;
    const code = err.code || 'DUPLICATE_EMAIL';

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      ...(details && { details }),
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  // Check for ConsentNotFoundError explicitly before PatientNotFoundError
  if (err?.name === 'ConsentNotFoundError' || err?.code === 'CONSENT_NOT_FOUND') {
    const status = 404;
    const code = 'CONSENT_NOT_FOUND';
    let message = err.message || 'Consent not found';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for ConsentExpiredError
  if (err?.name === 'ConsentExpiredError' || err?.code === 'CONSENT_EXPIRED') {
    const status = 410;
    const code = 'CONSENT_EXPIRED';
    let message = err.message || 'Consent has expired';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for InvalidConsentStatusError
  if (err?.name === 'InvalidConsentStatusError' || err?.code === 'INVALID_CONSENT_STATUS') {
    const status = 400;
    const code = 'INVALID_CONSENT_STATUS';
    let message = err.message || 'Invalid consent status';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for RecordNotFoundError explicitly before PatientNotFoundError
  if (err?.name === 'RecordNotFoundError' || err?.code === 'RECORD_NOT_FOUND') {
    const status = 404;
    const code = 'RECORD_NOT_FOUND';
    let message = err.message || 'Record not found';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for UserNotFoundError explicitly before PatientNotFoundError
  if (err?.name === 'UserNotFoundError' || err?.code === 'USER_NOT_FOUND') {
    const status = 404;
    const code = 'USER_NOT_FOUND';
    let message = err.message || 'User not found';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for PatientNotFoundError by name or code only (not generic NotFound)
  if (err?.name === 'PatientNotFoundError' ||
      err?.code === 'PATIENT_NOT_FOUND') {
    const status = 404;
    const code = 'PATIENT_NOT_FOUND';
    let message = err.message || 'Patient not found';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }
    
    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  // Check for ForbiddenError (must come BEFORE AccessDeniedError check)
  if (err?.name === 'ForbiddenError' || err?.code === 'FORBIDDEN') {
    const status = 403;
    const code = 'FORBIDDEN';
    let message = err.message || 'Forbidden';

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for CsrfValidationError specifically (must come BEFORE AccessDeniedError check)
  if (err?.name === 'CsrfValidationError' || err?.code === 'CSRF_VALIDATION_FAILED') {
    const status = 403;
    const code = 'CSRF_VALIDATION_FAILED';
    let message = err.message || 'CSRF validation failed';

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for AccessDeniedError by instanceof, name, or statusCode/code
  // NOTE: This should come AFTER specific 403 errors like ForbiddenError and CsrfValidationError
  if (err instanceof AccessDeniedError ||
      err?.name === 'AccessDeniedError' ||
      err?.code === 'ACCESS_DENIED') {
    const status = 403;
    const code = 'ACCESS_DENIED';
    let message = err.message;
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }
    
    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  // Check for TokenRotationError
  if (err?.name === 'TokenRotationError' || err?.code === 'TOKEN_ROTATION_ERROR') {
    const status = 401;
    const code = 'TOKEN_ROTATION_ERROR';
    let message = err.message || 'Token rotation failed';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for DatabaseConnectionError
  if (err?.name === 'DatabaseConnectionError' || err?.code === 'DATABASE_CONNECTION_ERROR') {
    const status = 500;
    const code = 'DATABASE_CONNECTION_ERROR';
    let message = err.message || 'Database connection failed';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for DatabaseQueryError
  if (err?.name === 'DatabaseQueryError' || err?.code === 'DATABASE_QUERY_ERROR') {
    const status = 500;
    const code = 'DATABASE_QUERY_ERROR';
    let message = err.message || 'Database query failed';
    try {
      message = localizeError(err, lang);
    } catch {
      // Localization failed, use default message
    }

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());

    return;
  }

  // Check for LocalizedError BUT only if it's not already handled by specific checks above
  // We check if statusCode is 500 and code is INTERNAL_ERROR (defaults) which means
  // it's a generic LocalizedError, not a specific subclass like PatientNotFoundError
  if (err instanceof LocalizedError &&
      err.statusCode === 500 &&
      err.code === 'INTERNAL_ERROR') {
    const status = 500;
    const code = 'INTERNAL_ERROR';
    const localizedMessage = localizeError(err, lang);
    
    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message: localizedMessage
      });
    } catch {
      // Logging failed, continue with error response
    }

    sendErrorResponse(res, status, {
      status,
      code,
      message: localizedMessage,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  // Check for HttpError by instanceof or statusCode property (for Jest module boundary issues)
  if ((err instanceof HttpError) || (err?.statusCode && typeof err.statusCode === 'number' && err.statusCode >= 400 && err.statusCode < 600)) {
    const status = err.statusCode;
    const code = err.code || `HTTP_${status}`;
    const message = err.message || 'An error occurred';
    const details = err.details;

    try {
      ErrorLogger.logError(err, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    const includeStack = process.env.NODE_ENV === 'development';

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      ...(details && { details }),
      ...(includeStack && { stack: err.stack })
    }, uuidv4());
    
    return;
  }

  if (err) {
    let errorObj: ErrorWithStatus;
    let status = 500;
    let message = 'An unknown error occurred';
    let code: string | undefined;
    let stackTrace: string | undefined;
    
    if (err instanceof Error) {
      errorObj = err as ErrorWithStatus;
      status = errorObj.status || 500;
      message = errorObj.message;
      code = errorObj.code;
      stackTrace = process.env.NODE_ENV === 'development' ? errorObj.stack : undefined;
    } else if (err !== undefined && err !== null) {
      message = `Non-error object thrown: ${String(err)}`;
      errorObj = new Error(message) as ErrorWithStatus;
      errorObj.status = 500;
    } else {
      // This branch should never be reached because we already checked for err !== undefined && err !== null
      // But just in case, we'll handle it
      errorObj = new Error('An undefined error occurred') as ErrorWithStatus;
      errorObj.status = 500;
      message = 'An undefined error occurred';
    }
    
    try {
      ErrorLogger.logError(errorObj, {
        path: req.path,
        method: req.method,
        status,
        message
      });
    } catch {
      // Logging failed, continue with error response
    }

    const errorResponse: any = {
      status,
      message,
      ...(stackTrace && { stack: stackTrace })
    };
    
    const excludeCodeErrors = [
      'ENOTFOUND',
      'ECONNREFUSED',
      'ETIMEDOUT'
    ];
    
    if (code && !excludeCodeErrors.includes(code)) {
      errorResponse.code = code;
    }

    sendErrorResponse(res, status, errorResponse, uuidv4());
  } else if (err === null) {
    ErrorLogger.logError('Error handler called with null error object', {
      path: req.path,
      method: req.method
    });
    
    sendErrorResponse(res, 500, {
      status: 500,
      message: 'Non-error object thrown: null'
    }, uuidv4());
  } else {
    ErrorLogger.logError('Error handler called with undefined error object', {
      path: req.path,
      method: req.method
    });
    
    sendErrorResponse(res, 500, {
      status: 500,
      message: 'Unknown error occurred'
    }, uuidv4());
  }
};

export default errorHandler;
