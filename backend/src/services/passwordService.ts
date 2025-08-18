/**
 * Password Service
 * 
 * Handles password generation, hashing, and validation.
 * 
 * For detailed validation rules, see: ../docs/PasswordValidation.md
 */
import bcrypt from 'bcrypt';
import { generate as generatePassword } from 'generate-password';
import zxcvbn from 'zxcvbn';
import { ValidationError } from '../errors/validationError';

export class PasswordService {
  generateTemporaryPassword() {
    return generatePassword({
      length: 12,
      numbers: true,
      symbols: true,
      uppercase: true,
      excludeSimilarCharacters: true,
      strict: true,
    });
  }

  async hashPassword(password: string) {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
  }

  validatePassword(password: string): void {
    const errors: { field: string; message: string }[] = [];

    const requirements = [
      { test: (p: string) => p.length >= 8, message: 'Minimum 8 characters' },
      { test: (p: string) => /[a-z]/.test(p), message: 'At least one lowercase letter' },
      { test: (p: string) => /[A-Z]/.test(p), message: 'At least one uppercase letter' },
      { test: (p: string) => /[0-9]/.test(p), message: 'At least one number' },
      { test: (p: string) => /[!@#$%^&*(),.?":{}|<>]/.test(p), message: 'At least one special character' }
    ];

    requirements.forEach(req => {
      if (!req.test(password)) {
        errors.push({ field: 'password', message: req.message });
      }
    });

    if (errors.length === 0) {
      const strength = zxcvbn(password).score;
      if (strength < 3) { // Medium strength threshold (0-4 scale)
        errors.push({ field: 'password', message: 'Password strength too weak' });
      }
    }

    if (errors.length > 0) {
      throw new ValidationError(errors);
    }
  }
}