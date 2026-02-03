import { LocalizedError } from './LocalizedError';
import { HttpError } from './httpErrors';

export class DatabaseConnectionError extends LocalizedError {
  constructor(message: string = 'Database connection failed') {
    super(message);
    this.statusCode = 500;
    this.code = 'DATABASE_CONNECTION_ERROR';
    this.name = 'DatabaseConnectionError';
  }
}

export class DuplicateRecordError extends HttpError {
  constructor(field: string, value: string) {
    if (field === 'email') {
      super(409, 'DUPLICATE_EMAIL', 'Email already exists', {
        errors: [{ field, message: 'Email is already in use' }]
      });
    } else {
      super(409, 'DUPLICATE_RECORD', `${field} '${value}' already exists`, {
        field,
        value
      });
    }
  }
}

export class RecordNotFoundError extends LocalizedError {
  constructor(recordType: string, identifier: string) {
    super(`${recordType} with identifier ${identifier} not found`, recordType, identifier);
    this.statusCode = 404;
    this.code = 'RECORD_NOT_FOUND';
    this.name = 'RecordNotFoundError';
  }
}

export class DatabaseQueryError extends LocalizedError {
  constructor(message: string = 'Database query failed') {
    super(message);
    this.statusCode = 500;
    this.code = 'DATABASE_QUERY_ERROR';
    this.name = 'DatabaseQueryError';
  }
}