import logger from './logger';

/**
 * Centralized error logger utility that filters sensitive data
 * and obfuscates stack traces in production
 */
class ErrorLogger {
  /**
   * Log error with appropriate level of detail based on environment
   * @param error The error to log
   * @param context Additional context information
   * @param level Log level (default: 'error')
   */
  static log(
    error: any,
    context: Record<string, any> = {},
    level: string = 'error'
  ): void {
    const errorMessage =
      error instanceof Error ? error.message : String(error);
    const errorStack =
      error instanceof Error ? error.stack : undefined;

    const isDevelopment = process.env.NODE_ENV === 'development';

    const logData: Record<string, any> = {
      message: errorMessage,
      ...context,
    };

    if (isDevelopment && errorStack) {
      logData.stack = errorStack;
    }

    switch (level) {
      case 'error':
        logger.error(logData);
        break;
      case 'warn':
        logger.warn(logData);
        break;
      case 'info':
        logger.info(logData);
        break;
      default:
        logger.error(logData);
    }
  }

  /**
   * Log error with filtering of sensitive data
   * @param error The error to log
   * @param context Additional context information
   */
  static logError(
    error: any,
    context: Record<string, any> = {}
  ): void {
    const filteredContext = this.filterSensitiveData(context);
    this.log(error, filteredContext, 'error');
  }

  /**
   * Log warning with filtering of sensitive data
   * @param error The error to log
   * @param context Additional context information
   */
  static logWarning(
    error: any,
    context: Record<string, any> = {}
  ): void {
    const filteredContext = this.filterSensitiveData(context);
    this.log(error, filteredContext, 'warn');
  }

  /**
   * Filter sensitive data from context
   * @param context Context object to filter
   * @returns Filtered context object
   */
  private static filterSensitiveData(
    context: Record<string, any>
  ): Record<string, any> {
    const filteredContext = { ...context };

    const sensitiveFields = [
      'password',
      'token',
      'authorization',
      'cookie',
      'secret',
      'key',
      'credential',
    ];

    for (const [key, value] of Object.entries(filteredContext)) {
      const lowerKey = key.toLowerCase();
      if (sensitiveFields.some((field) => lowerKey.includes(field))) {
        filteredContext[key] = '[REDACTED]';
      } else if (typeof value === 'object' && value !== null) {
        filteredContext[key] = this.filterSensitiveData(value);
      }
    }

    return filteredContext;
  }
}

export default ErrorLogger;
