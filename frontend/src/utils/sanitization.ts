import DOMPurify from 'dompurify';

/**
 * Sanitizes user input to prevent XSS attacks
 * @param input - The string to sanitize
 * @returns Sanitized string
 */
export const sanitizeInput = (input: string): string => {
  return DOMPurify.sanitize(input);
};

/**
 * Sanitizes user input that may be null or undefined
 * @param value - The value to sanitize
 * @returns Sanitized string or the original value if null/undefined
 */
export const sanitizeInputNullable = (value: string | null | undefined): string | null | undefined => {
  if (value === null || value === undefined) {
    return value;
  }
  return DOMPurify.sanitize(value);
};

/**
 * Sanitizes user input with a fallback to empty string for required fields
 * @param value - The value to sanitize
 * @param fallback - The fallback value if the input is null or undefined
 * @returns Sanitized string
 */
export const sanitizeInputWithFallback = (value: string | null | undefined, fallback: string = ''): string => {
  if (value === null || value === undefined) {
    return fallback;
  }
  return DOMPurify.sanitize(value);
};

/**
 * Sanitizes HTML content for safe display
 * @param content - The HTML content to sanitize
 * @returns Sanitized HTML string
 */
export const sanitizeOutput = (content: string): string => {
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'span'],
    ALLOWED_ATTR: ['class', 'style']
  });
};

/**
 * Sanitizes medical history data for safe display
 * @param content - The medical history content to sanitize
 * @returns Sanitized HTML string
 */
export const sanitizeMedicalHistory = (content: string): string => {
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'span', 'div'],
    ALLOWED_ATTR: ['class', 'style']
  });
};