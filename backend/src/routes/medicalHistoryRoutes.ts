import { Router, Request, Response, NextFunction } from 'express';
import { MedicalHistory } from '../entities/MedicalHistory';
import { AppDataSource } from '../index';
import {
  MedicalHistoryCreateSchema,
  MedicalHistoryUpdateSchema,
} from '../schemas/medicalHistorySchemas';
import asyncHandler from '../utils/asyncHandler';
import { Patient } from '../entities/Patient';
import {
  authenticateJWT,
  authorizeRole,
} from '../middlewares/authMiddleware';
import DOMPurify from 'isomorphic-dompurify';
import { validate } from '../middlewares/validationMiddleware';
import { z } from 'zod';
import { HttpError, NotFoundError } from '../errors/httpErrors';
import { getPatientService } from './patientRoutes';
import { PatientNotFoundError } from '../errors/patientErrors';

const verifyMedicalHistoryAccess = async (req: Request, _res: Response, next: NextFunction) => {
  try {
    const { id } = req.params;
    if (!id || isNaN(Number(id))) {
      next(new HttpError(400, 'INVALID_MEDICAL_HISTORY_ID', 'Invalid medical history ID'));
      return;
    }

    const medicalHistoryId = parseInt(id);
    const medicalHistory = await AppDataSource.getRepository(MedicalHistory).findOne({
      where: { id: medicalHistoryId },
      relations: ['patient'],
    });

    if (!medicalHistory) {
      next(new NotFoundError('Medical history not found'));
      return;
    }

    const patient = await getPatientService().getPatientById(medicalHistory.patient.id, { id: req.user!.id });
    
    if (!patient) {
      next(new PatientNotFoundError());
      return;
    }

    if (req.user?.role === 'patient' && patient.id !== req.user.id) {
      next(new HttpError(403, 'ACCESS_DENIED', 'Access forbidden'));
      return;
    }

    (req as any).medicalHistory = medicalHistory;
    next();
  } catch (error) {
    next(error);
  }
};

/**
 * Medical History Routes
 *
 * All routes in this file require JWT authentication.
 *
 * @route GET,POST,PUT,DELETE /medical-history
 */
const router = Router();
router.use(asyncHandler(authenticateJWT));

const authorizeAdminClinician = authorizeRole(['admin', 'clinician']);
const authorizePatientAccess = authorizeRole(['patient', 'admin', 'clinician', 'staff']);
const authorizeAdminOnly = authorizeRole(['admin']);

router.post(
  '/',
  authorizeAdminClinician,
  validate(MedicalHistoryCreateSchema),
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const validatedData = req.validatedData as z.infer<typeof MedicalHistoryCreateSchema>;
    const patient = await AppDataSource.getRepository(
      Patient
    ).findOneBy({
      id: validatedData.patientId,
    });

    if (!patient) {
      next(new PatientNotFoundError());
      return;
    }

    const medicalHistoryRepo =
      AppDataSource.getRepository(MedicalHistory);
    const sanitizedNotes = DOMPurify.sanitize(validatedData.notes || '');
    const medicalHistory = medicalHistoryRepo.create({
      ...validatedData,
      patient,
      notes: sanitizedNotes,
    });

    const result = await medicalHistoryRepo.save(medicalHistory);
    res.status(201).json(result);
  })
);

router.get(
  '/:id',
  authorizePatientAccess,
  asyncHandler(verifyMedicalHistoryAccess),
  asyncHandler(async (req: Request, res: Response, _next: NextFunction) => {
    const medicalHistory = (req as any).medicalHistory;
    res.json(medicalHistory);
  })
);

router.get(
  '/patient/:patientId',
  authorizePatientAccess,
  asyncHandler(async (req: Request, res: Response, _next: NextFunction) => {
    const histories = await AppDataSource.getRepository(MedicalHistory).find({
      where: { patient: { id: parseInt(req.params.patientId as string) } },
      relations: ['patient'],
      order: { date: 'DESC' },
    });
    
    if (!histories || histories.length === 0) {
      res.json([]);
      return;
    }
    
    res.json(histories);
  })
);

router.put(
  '/:id',
  authorizeAdminClinician,
  validate(MedicalHistoryUpdateSchema),
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const validatedData = req.validatedData as z.infer<typeof MedicalHistoryUpdateSchema>;
    const medicalHistoryRepo =
      AppDataSource.getRepository(MedicalHistory);

    const existing = await medicalHistoryRepo.findOneBy({
      id: parseInt(req.params.id as string),
    });

    if (!existing) {
      next(new NotFoundError('Medical history not found'));
      return;
    }

    let patient: Patient | null = null;
    if (validatedData.patientId) {
      patient = await AppDataSource.getRepository(Patient).findOneBy({
        id: validatedData.patientId,
      });
      if (!patient) {
        next(new PatientNotFoundError());
        return;
      }
    }

    const updateData = { ...validatedData };
    if (updateData.notes) {
      updateData.notes = DOMPurify.sanitize(updateData.notes);
    } else if (updateData.notes === null || updateData.notes === undefined) {
      updateData.notes = '';
    }
    
    const updated = await medicalHistoryRepo.save({
      ...existing,
      ...updateData,
      ...(patient ? { patient } : {}),
    });
    res.json(updated);
  })
);

router.delete(
  '/:id',
  authorizeAdminOnly,
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const result = await AppDataSource.getRepository(
      MedicalHistory
    ).delete(parseInt(req.params.id as string));

    if (result.affected === 0) {
      next(new NotFoundError('Medical history not found'));
      return;
    }
    res.status(204).send();
  })
);

export default router;
