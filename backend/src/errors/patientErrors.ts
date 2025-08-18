import { LocalizedError } from './LocalizedError';

export class PatientNotFoundError extends LocalizedError {
  constructor() {
    super('Patient not found');
    this.statusCode = 404;
    this.code = 'PATIENT_NOT_FOUND';
  }
}