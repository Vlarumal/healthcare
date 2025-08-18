import { LocalizedError } from './LocalizedError';

export class ConsentNotFoundError extends LocalizedError {
  constructor(public consentId: number) {
    super('Consent with id {0} not found', consentId);
    this.statusCode = 404;
    this.code = 'CONSENT_NOT_FOUND';
  }
}

export class ConsentExpiredError extends LocalizedError {
  constructor(public consentId: number) {
    super('Consent with id {0} has expired', consentId);
    this.statusCode = 410;
    this.code = 'CONSENT_EXPIRED';
  }
}

export class InvalidConsentStatusError extends LocalizedError {
  constructor(public consentId: number, status: string) {
    super('Consent with id {0} has invalid status: {1}', consentId, status);
    this.statusCode = 400;
    this.code = 'INVALID_CONSENT_STATUS';
  }
}