import { safeDateConversion, calculatePatientAge } from '../dateUtils';

describe('dateUtils', () => {
  describe('safeDateConversion', () => {
    it('should return null for undefined input', () => {
      expect(safeDateConversion(undefined)).toBeNull();
    });

    it('should return the same Date object if input is already a Date', () => {
      const date = new Date('1990-01-01');
      expect(safeDateConversion(date)).toBe(date);
    });

    it('should convert valid date strings to Date objects', () => {
      const result = safeDateConversion('1990-01-01');
      expect(result).toBeInstanceOf(Date);
      expect(result?.toISOString()).toContain('1990-01-01');
    });

    it('should return null for invalid date strings', () => {
      expect(safeDateConversion('invalid-date')).toBeNull();
    });

    it('should return null for empty strings', () => {
      expect(safeDateConversion('')).toBeNull();
    });
  });

  describe('calculatePatientAge', () => {
    it('should calculate age correctly for valid Date objects', () => {
      const patient = {
        dateOfBirth: new Date('1990-01-01')
      };
      
      const age = calculatePatientAge(patient as any);
      expect(age).toBeGreaterThanOrEqual(30);
      expect(age).toBeLessThanOrEqual(100);
    });

    it('should calculate age correctly for valid date strings', () => {
      const patient = {
        dateOfBirth: '1990-01-01'
      };
      
      const age = calculatePatientAge(patient as any);
      expect(age).toBeGreaterThanOrEqual(30);
      expect(age).toBeLessThanOrEqual(100);
    });

    it('should return null for patients with invalid dateOfBirth', () => {
      const patient = {
        dateOfBirth: 'invalid-date'
      };
      
      expect(calculatePatientAge(patient as any)).toBeNull();
    });

    it('should return null for patients with null dateOfBirth', () => {
      const patient = {
        dateOfBirth: null
      };
      
      expect(calculatePatientAge(patient as any)).toBeNull();
    });

    it('should return null for patients with undefined dateOfBirth', () => {
      const patient = {
        dateOfBirth: undefined
      };
      
      expect(calculatePatientAge(patient as any)).toBeNull();
    });

    it('should return null for patients with future dates', () => {
      const futureDate = new Date();
      futureDate.setFullYear(futureDate.getFullYear() + 1);
      
      const patient = {
        dateOfBirth: futureDate
      };
      
      expect(calculatePatientAge(patient as any)).toBeNull();
    });

    it('should return null for patients with unreasonably old dates', () => {
      const veryOldDate = new Date('1800-01-01');
      
      const patient = {
        dateOfBirth: veryOldDate
      };
      
      expect(calculatePatientAge(patient as any)).toBeNull();
    });
  });
});
