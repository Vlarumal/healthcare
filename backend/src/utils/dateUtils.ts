import { Patient } from '../entities/Patient';

/**
 * Safely converts a date value to a Date object
 * @param dateValue - The date value to convert (can be Date, string, or undefined)
 * @returns A Date object or null if conversion fails
 */
export function safeDateConversion(dateValue: Date | string | undefined): Date | null {
  if (!dateValue) {
    return null;
  }
  
  if (dateValue instanceof Date) {
    return dateValue;
  }
  
  if (typeof dateValue === 'string') {
    const parsedDate = new Date(dateValue);
    if (!isNaN(parsedDate.getTime())) {
      return parsedDate;
    }
  }
  
  return null;
}

/**
 * Calculates the age of a patient based on their date of birth
 * @param patient - The patient object
 * @returns The age in years, or null if dateOfBirth is invalid
 */
export function calculatePatientAge(patient: Patient): number | null {
  const birthDate = safeDateConversion(patient.dateOfBirth);
  
  if (!birthDate) {
    return null;
  }
  
  const today = new Date();
  const age = Math.floor((today.getTime() - birthDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25));
  
  if (age < 0 || age > 150) {
    return null;
  }
  
  return age;
}