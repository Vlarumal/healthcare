import { HttpError } from './httpErrors';

export class LocalizedError extends HttpError {
  constructor(message: string, ...args: any[]) {
    // Default to 500 status code and INTERNAL_ERROR code for localized errors
    super(500, 'INTERNAL_ERROR', message, undefined, ...args);
    this.name = this.constructor.name;
  }
}