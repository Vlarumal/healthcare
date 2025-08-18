import { Router, Request, Response, NextFunction } from 'express';
import {
  authenticateJWT,
  authorizeRole,
} from '../middlewares/authMiddleware';
import { Gender, Patient } from '../entities/Patient';
import { AppDataSource } from '../index';
import {
  PatientCreateSchema,
  PatientUpdateSchema,
} from '../schemas/patientSchemas';
import { PatientSortSchema } from '../schemas/patientSchemas';
import { PasswordService } from '../services/passwordService';
import { AuditService } from '../services/AuditService';
import { EmailService } from '../services/emailService';
import { transporter } from '../utils/mailer';
import logger from '../utils/logger';
import { PatientService } from '../services/PatientService';
import { PatientNotFoundError } from '../errors/patientErrors';
import { validate } from '../middlewares/validationMiddleware';
import { z } from 'zod';
import {
  HttpError,
  InternalServerError,
  AccessDeniedError,
} from '../errors/httpErrors';
import { DuplicateRecordError } from '../errors/databaseErrors';

/**
 * Patient Routes
 *
 * All routes in this file require JWT authentication.
 *
 * @route GET,POST,PUT,DELETE /patients
 */
const router = Router();
router.use(authenticateJWT);

export function createPatientService() {
  if (!AppDataSource.isInitialized) {
    throw new Error('AppDataSource not initialized!');
  }
  
  const auditService = new AuditService();
  const passwordService = new PasswordService();
  const emailService = new EmailService(transporter, logger);
  
  return PatientService({
    patientRepository: AppDataSource.getRepository(Patient),
    auditService,
    passwordService,
    emailService,
  });
}

let defaultPatientService: ReturnType<typeof PatientService> | null = null;

export function getPatientService() {
  if (!defaultPatientService) {
    defaultPatientService = createPatientService();
  }
  return defaultPatientService;
}

export function resetPatientService() {
  defaultPatientService = null;
}
const authorizeAdminClinician = authorizeRole(['admin', 'clinician']);
const authorizePatientAccess = authorizeRole([
  'patient',
  'admin',
  'clinician',
  'staff',
  'guest',
]);
const authorizeAdminOnly = authorizeRole(['admin']);

const authorizeRoleModification = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  const validatedData = req.validatedData as any;
  if (validatedData && validatedData.role !== undefined) {
    if (!req.user || req.user.role !== 'admin') {
      next(
        new HttpError(
          403,
          'ACCESS_DENIED',
          'Only administrators can modify user roles'
        )
      );
      return;
    }
  }
  next();
};

router.post(
  '/',
  authorizeAdminClinician,
  validate(PatientCreateSchema),
  async (req, res, next) => {
    try {
      const validatedData = req.validatedData as z.infer<
        typeof PatientCreateSchema
      >;

      const {
        firstName,
        lastName,
        email,
        dateOfBirth,
        gender,
        phoneNumber,
      } = validatedData;
      const inputData = {
        firstName,
        lastName,
        email,
        dateOfBirth: new Date(dateOfBirth),
        gender: gender || Gender.UNSPECIFIED,
        phoneNumber,
      };

      const newPatient = await getPatientService().createPatient(
        inputData,
        { id: req.user!.id }
      );

      // Sanitize response - remove password field
      const { password, ...sanitizedPatient } = newPatient;
      res.status(201).json(sanitizedPatient);
    } catch (error) {
      if (
        error instanceof Error &&
        error.message === 'AppDataSource not initialized!'
      ) {
        next(new InternalServerError('Database connection error'));
      } else if ((error as any).code === '23505') {
        next(new DuplicateRecordError('email', req.body.email));
      } else if (error instanceof DuplicateRecordError) {
        next(error);
      } else if (error instanceof Error) {
        logger.error('Error creating patient:', error);
        next(new InternalServerError(error.message));
      } else {
        logger.error('Unexpected error creating patient:', error);
        next(new InternalServerError('An unexpected error occurred'));
      }
    }
  }
);

export const verifyPatientOwnership = async (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  try {
    const resolvedId = parseInt(req.params.id);
    if (isNaN(resolvedId)) {
      next(
        new HttpError(400, 'INVALID_PATIENT_ID', 'Invalid patient ID')
      );
      return;
    }

    const patient = await getPatientService().getPatientById(
      resolvedId,
      { id: req.user!.id }
    );

    if (!patient) {
      next(new PatientNotFoundError());
      return;
    }

    const isSelfAccess = patient.id === req.user!.id;
    const isAuthorizedRole = ['admin', 'clinician', 'staff'].includes(
      req.user!.role
    );

    if (!(isAuthorizedRole || isSelfAccess)) {
      next(new AccessDeniedError('Access forbidden'));
      return;
    }

    (req as any).patient = patient;
    next();
  } catch (error) {
    if (error instanceof HttpError || error instanceof PatientNotFoundError || error instanceof AccessDeniedError) {
      next(error);
      return;
    } else if (error instanceof Error) {
      logger.error('Patient ownership verification failed:', error);
      next(new InternalServerError(error.message));
      return;
    } else {
      logger.error('Unexpected error verifying patient ownership:', error);
      next(new InternalServerError('An unexpected error occurred'));
      return;
    }
  }
};

router.put(
  '/:id',
  authorizeAdminClinician,
  verifyPatientOwnership,
  validate(PatientUpdateSchema),
  authorizeRoleModification,
  async (req: Request, res, next) => {
    try {
      const validatedData = req.validatedData as z.infer<
        typeof PatientUpdateSchema
      >;

      const patientId = parseInt(req.params.id);
      if (isNaN(patientId)) {
        next(
          new HttpError(
            400,
            'INVALID_PATIENT_ID',
            'Invalid patient ID'
          )
        );
        return;
      }

      const hasUpdateData = Object.values(validatedData).some(
        (value) => value !== undefined
      );
      if (!hasUpdateData) {
        const patient = await getPatientService().getPatientById(
          patientId,
          { id: req.user!.id }
        );
        if (!patient) {
          next(new PatientNotFoundError());
          return;
        }
        const { password: _, ...patientData } = patient;
        res.status(200).json(patientData);
        return;
      }

      const updateData: Partial<Patient> = {};

      type PatientUpdateData = z.infer<typeof PatientUpdateSchema>;
      const allowedFields: (keyof PatientUpdateData)[] = [
        'firstName',
        'lastName',
        'email',
        'gender',
        'phoneNumber',
        'address',
        'city',
        'zipCode',
        'role',
      ];

      // Copy allowed fields with explicit type conversion
      // For nullable fields (zipCode, address, city, phoneNumber), convert undefined to null
      for (const field of allowedFields) {
        if (field in validatedData) {
          const value = validatedData[field];
          if (
            value === undefined &&
            ['zipCode', 'address', 'city', 'phoneNumber'].includes(
              field
            )
          ) {
            (updateData as any)[field] = null;
          } else {
            (updateData as any)[field] = value;
          }
        }
      }

      if (validatedData.dateOfBirth) {
        updateData.dateOfBirth = new Date(validatedData.dateOfBirth);
      }

      const updatedPatient = await getPatientService().updatePatient(
        patientId,
        updateData,
        { id: req.user!.id }
      );

      // Sanitize response - remove password field
      const { password, ...sanitizedPatient } = updatedPatient;
      res.status(200).json(sanitizedPatient);
    } catch (error) {
      if ((error as any).code === '23505') {
        next(new DuplicateRecordError('email', req.body.email));
      } else if (error instanceof PatientNotFoundError) {
        next(new PatientNotFoundError());
      } else if (error instanceof Error) {
        logger.error('Patient update failed:', error);
        next(new InternalServerError(error.message));
      } else {
        logger.error('Unexpected error updating patient:', error);
        next(new InternalServerError('An unexpected error occurred'));
      }
    }
  }
);

router.patch(
  '/:id',
  authorizeAdminClinician,
  verifyPatientOwnership,
  validate(PatientUpdateSchema),
  authorizeRoleModification,
  async (req: Request, res, next) => {
    try {
      const validatedData = req.validatedData as z.infer<
        typeof PatientUpdateSchema
      >;

      const patientId = parseInt(req.params.id);
      if (isNaN(patientId)) {
        next(
          new HttpError(
            400,
            'INVALID_PATIENT_ID',
            'Invalid patient ID'
          )
        );
        return;
      }

      type PatientUpdateData = z.infer<typeof PatientUpdateSchema>;
      const allowedFields: (keyof PatientUpdateData)[] = [
        'firstName',
        'lastName',
        'email',
        'gender',
        'phoneNumber',
        'address',
        'city',
        'zipCode',
        'role',
      ];

      // Check if update data is empty
      // For PATCH requests, we need to check if any allowed fields are present in the request,
      // even if their values are undefined (which would be the case for clearing a field)
      const hasUpdateData = allowedFields.some(
        (field) => field in validatedData
      );
      if (!hasUpdateData) {
        const patient = await getPatientService().getPatientById(
          patientId,
          { id: req.user!.id }
        );
        if (!patient) {
          next(new PatientNotFoundError());
          return;
        }
        const { password: _, ...patientData } = patient;
        res.status(200).json(patientData);
        return;
      }

      const updateData: Partial<Patient> = {};

      // For nullable fields (zipCode, address, city, phoneNumber), convert undefined to null
      for (const field of allowedFields) {
        if (field in validatedData) {
          const value = validatedData[field];
          if (
            value === undefined &&
            ['zipCode', 'address', 'city', 'phoneNumber'].includes(
              field
            )
          ) {
            (updateData as any)[field] = null;
          } else {
            (updateData as any)[field] = value;
          }
        }
      }

      if (validatedData.dateOfBirth) {
        updateData.dateOfBirth = new Date(validatedData.dateOfBirth);
      }

      const updatedPatient = await getPatientService().updatePatient(
        patientId,
        updateData,
        { id: req.user!.id }
      );

      // Sanitize response - remove password field
      const { password, ...sanitizedPatient } = updatedPatient;
      res.status(200).json(sanitizedPatient);
    } catch (error) {
      if ((error as any).code === '23505') {
        next(new DuplicateRecordError('email', req.body.email));
      } else if (error instanceof PatientNotFoundError) {
        next(new PatientNotFoundError());
      } else if (error instanceof Error) {
        logger.error('Patient update failed:', error);
        next(new InternalServerError(error.message));
      } else {
        logger.error('Unexpected error updating patient:', error);
        next(new InternalServerError('An unexpected error occurred'));
      }
    }
  }
);

router.get('/', authorizePatientAccess, async (req, res, next) => {
  try {
    const {
      page = 1,
      pageSize = 10,
      sort = 'id',
      order = 'ASC',
      ...rawFilters
    } = req.query;

    const sortValidation = PatientSortSchema.safeParse({
      sortBy: sort,
      sortOrder: order,
    });

    if (!sortValidation.success) {
      next(
        new HttpError(
          400,
          'INVALID_SORT_PARAMETER',
          'Invalid sort parameter',
          {
            errors: sortValidation.error.issues,
          }
        )
      );
      return;
    }

    const validSortBy = sortValidation.data.sortBy || 'id';
    const validSortOrder = sortValidation.data.sortOrder || 'ASC';

    if (req.user?.role === 'patient') {
      rawFilters.id = req.user.id.toString();
    }

    const allowedFilters = [
      'id',
      'firstName',
      'lastName',
      'email',
      'gender',
      'startDate',
      'endDate',
      'role',
    ];
    const filters = Object.keys(rawFilters)
      .filter(
        (key) =>
          allowedFilters.includes(key) &&
          (typeof rawFilters[key] === 'string' ||
            rawFilters[key] instanceof Date)
      )
      .reduce((obj, key) => {
        obj[key] =
          rawFilters[key] instanceof Date
            ? (rawFilters[key] as Date).toISOString()
            : (rawFilters[key] as string);
        return obj;
      }, {} as Record<string, string>);

    const result = await getPatientService().getPatients(
      Number(page),
      Number(pageSize),
      filters,
      {
        field: validSortBy,
        direction: validSortOrder,
        caseInsensitive: true,
      }
    );

    logger.info('Patient list accessed', {
      userId: req.user?.id,
      role: req.user?.role,
      filters,
      resultCount: result.data ? result.data.length : 0,
    });

    res.json(result);
  } catch (error) {
    if (error instanceof Error) {
      logger.error('Patient list retrieval failed:', error);

      if (error.message.startsWith('Invalid')) {
        next(
          new HttpError(400, 'VALIDATION_ERROR', error.message, {
            errors: [error.message],
          })
        );
      } else {
        next(new InternalServerError(error.message));
      }
    } else {
      logger.error('Unexpected error retrieving patient list:', error);
      next(new InternalServerError('An unexpected error occurred'));
    }
  }
});

router.get('/me', authorizePatientAccess, async (req, res, next) => {
  try {
    const patient = await getPatientService().getPatientById('me', {
      id: req.user!.id,
    });

    if (!patient) {
      throw new PatientNotFoundError();
    }

    // Sanitize response - remove sensitive fields
    const { password, ...sanitizedPatient } = patient;
    res.json(sanitizedPatient);
  } catch (error) {
    if (error instanceof PatientNotFoundError) {
      next(new PatientNotFoundError());
    } else {
      logger.error('Patient retrieval failed: %o', error);
      next(new InternalServerError('An unexpected error occurred'));
    }
  }
});

router.get(
  '/:id',
  authorizePatientAccess,
  verifyPatientOwnership,
  async (req, res, next) => {
    try {
      const patient = (req as any).patient;

      // Sanitize response - remove sensitive fields
      const { password, ...sanitizedPatient } = patient;
      res.json(sanitizedPatient);
    } catch (error) {
      if (error instanceof PatientNotFoundError) {
        next(new PatientNotFoundError());
      } else if (error instanceof Error) {
        logger.error('Patient retrieval failed:', error);
        next(new InternalServerError(error.message));
      } else {
        logger.error('Unexpected error retrieving patient:', error);
        next(new InternalServerError('An unexpected error occurred'));
      }
    }
  }
);

router.delete('/:id', authorizeAdminOnly, async (req, res, next) => {
  try {
    const patientId = parseInt(req.params.id);
    if (isNaN(patientId)) {
      next(
        new HttpError(400, 'INVALID_PATIENT_ID', 'Invalid patient ID')
      );
      return;
    }
    await getPatientService().deletePatient(patientId, {
      id: req.user!.id,
    });
    res.status(204).send();
  } catch (error) {
    if (error instanceof PatientNotFoundError) {
      next(new PatientNotFoundError());
    } else if (error instanceof Error) {
      logger.error('Patient deletion failed:', error);
      next(new InternalServerError(error.message));
    } else {
      logger.error('Unexpected error deleting patient:', error);
      next(new InternalServerError('An unexpected error occurred'));
    }
  }
});

export default router;
