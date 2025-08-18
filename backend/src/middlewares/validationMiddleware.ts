import { Request, Response, NextFunction } from 'express';
import { AnyZodObject, ZodError } from 'zod';
import { ValidationError } from '../errors/validationError';
import logger from '../utils/logger';

/**
 * Validation middleware that uses Zod schemas to validate request data
 * @param schema Zod schema to validate against (can validate body, query, and params)
 */
export const validate = (schema: AnyZodObject) =>
  (req: Request, _res: Response, next: NextFunction) => {
    try {
      logger.info('Validation middleware called with body:', req.body);
      const result = schema.safeParse(req.body);
      logger.info('Validation result:', result);

      if (!result.success) {
        logger.error('Validation failed for request body:', { body: req.body });
        logger.error('Validation errors:', { errors: result.error.errors });
        
        const errors = result.error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));
        
        throw new ValidationError(errors);
      }

      req.validatedData = result.data;
      logger.info('Validation successful, validated data:', result.data);
      next();
    } catch (err) {
      console.log('Validation middleware caught error:', err);
      if (err instanceof ValidationError) {
        next(err);
      } else if (err instanceof ZodError) {
        const errors = err.errors.map(e => ({
          field: e.path.join('.'),
          message: e.message
        }));
        next(new ValidationError(errors));
      } else {
        logger.error('Unexpected error in validation middleware:', err);
        next(err);
      }
    }
  };