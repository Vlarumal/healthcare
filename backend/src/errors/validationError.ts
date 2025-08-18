import { HttpError } from './httpErrors';

export class ValidationError extends HttpError {
  public details: { field: string; message: string }[];

  constructor(errors: { field: string; message: string }[]) {
    super(400, 'VALIDATION_ERROR', 'Validation failed');
    this.name = 'ValidationError';
    this.details = errors;
  }
}