/**
 * Centralized configuration service for environment variables and constants.
 * Provides type-safe access to configuration values.
 */
export function getGuestPassword(): string | undefined {
  return import.meta.env.VITE_GUEST_PASSWORD;
}
