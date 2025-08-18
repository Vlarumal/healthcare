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

    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message,
      ...(err?.id && { errorId: err.id })
    });

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      details: details.length > 0 ? { errors: details } : undefined,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  if (err && err.code === 'DUPLICATE_EMAIL') {
    const status = 409;
    const message = 'Email already exists';
    const details = err.details;
    const code = 'DUPLICATE_EMAIL';

    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message
    });

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      ...(details && { details }),
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  if (err instanceof AccessDeniedError) {
    const status = 403;
    const code = 'ACCESS_DENIED';
    let message = err.message;
    try {
      message = localizeError(err, lang);
    } catch (e) {
      ErrorLogger.logError(e, { message: 'Localization failed for AccessDeniedError' });
    }
    
    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message
    });

    sendErrorResponse(res, status, {
      status,
      code,
      message,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  if (err instanceof LocalizedError) {
    const status = err.statusCode || 500;
    const code = err.code || 'INTERNAL_ERROR';
    const localizedMessage = localizeError(err, lang);
    
    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message: localizedMessage
    });

    sendErrorResponse(res, status, {
      status,
      code,
      message: localizedMessage,
      stack: err.stack
    }, uuidv4());
    
    return;
  }

  if (err instanceof HttpError) {
    const status = err.statusCode;
    const code = err.code || `HTTP_${status}`;
    const message = err.message || 'An error occurred';
    const details = err.details;

    ErrorLogger.logError(err, {
      path: req.path,
      method: req.method,
      status,
      message
    });

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
    
    ErrorLogger.logError(errorObj, {
      path: req.path,
      method: req.method,
      status,
      message
    });

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
