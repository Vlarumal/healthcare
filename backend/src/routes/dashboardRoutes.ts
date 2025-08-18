import { Router, Request, Response, NextFunction } from 'express';
import {
  authenticateJWT,
  authorizeRole,
} from '../middlewares/authMiddleware';
import asyncHandler from '../utils/asyncHandler';
import { AppDataSource } from '../data-source';
import { Patient, Role } from '../entities/Patient';
import { MedicalHistory } from '../entities/MedicalHistory';
import logger from '../utils/logger';
import { InternalServerError } from '../errors/httpErrors';
import { MoreThan, Between, IsNull } from 'typeorm';

/**
 * Dashboard Routes
 *
 * All routes in this file require JWT authentication and admin role access.
 *
 * @route GET /api/dashboard/*
 */
const router = Router();

router.use(authenticateJWT);

router.use(authorizeRole(['admin']));

const getPatientRepository = () => AppDataSource.getRepository(Patient);
const getMedicalHistoryRepository = () => AppDataSource.getRepository(MedicalHistory);

/**
 * @route GET /api/dashboard/patient-metrics
 * @desc Get patient statistics metrics
 * @access Admin
 */
router.get('/patient-metrics', asyncHandler(async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const patientRepo = getPatientRepository();
    
    const totalPatients = await patientRepo.count({
      where: {
        deletedAt: IsNull()
      },
      cache: {
        id: 'dashboard:patientMetrics:totalPatients',
        milliseconds: 300000 // 5 minutes
      }
    });
    
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const newPatients7Days = await patientRepo.count({
      where: {
        createdAt: MoreThan(sevenDaysAgo),
        deletedAt: IsNull()
      },
      cache: {
        id: 'dashboard:patientMetrics:newPatients7Days',
        milliseconds: 300000
      }
    });
    
    const newPatients30Days = await patientRepo.count({
      where: {
        createdAt: MoreThan(thirtyDaysAgo),
        deletedAt: IsNull()
      },
      cache: {
        id: 'dashboard:patientMetrics:newPatients30Days',
        milliseconds: 300000
      }
    });
    
    const ageGroupsResult = await AppDataSource.query(`
      SELECT
        CASE
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 18 THEN '0-17'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 35 THEN '18-34'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 50 THEN '35-49'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 65 THEN '50-64'
          ELSE '65+'
        END as age_group,
        COUNT(*) as count
      FROM patient
      WHERE "deleted_at" IS NULL
      GROUP BY
        CASE
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 18 THEN '0-17'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 35 THEN '18-34'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 50 THEN '35-49'
          WHEN EXTRACT(YEAR FROM AGE("dateOfBirth")) < 65 THEN '50-64'
          ELSE '65+'
        END
    `);
    
    const ageGroups: Record<string, number> = {
      '0-17': 0,
      '18-34': 0,
      '35-49': 0,
      '50-64': 0,
      '65+': 0
    };
    
    ageGroupsResult.forEach((row: any) => {
      ageGroups[row.age_group] = parseInt(row.count);
    });
    
    const genderDistributionResult = await AppDataSource.query(`
      SELECT
        COALESCE(gender, 'unspecified') as gender,
        COUNT(*) as count
      FROM patient
      WHERE "deleted_at" IS NULL
      GROUP BY gender
    `);
    
    const genderDistribution: Record<string, number> = {
      'male': 0,
      'female': 0,
      'other': 0,
      'unspecified': 0
    };
    
    genderDistributionResult.forEach((row: any) => {
      const gender = row.gender || 'unspecified';
      genderDistribution[gender] = parseInt(row.count);
    });
    
    
    // For status distribution, we'll use role as a proxy since we don't have explicit status field
    const statusDistribution = {
      active: await patientRepo.count({
        where: { role: Role.PATIENT, deletedAt: IsNull() },
        cache: {
          id: 'dashboard:patientMetrics:statusDistribution:active',
          milliseconds: 300000
        }
      }),
      discharged: 0, // We don't have this data in current schema
      followUpNeeded: 0 // We don't have this data in current schema
    };
    
    res.json({
      totalPatients,
      newPatients: {
        last7Days: newPatients7Days,
        last30Days: newPatients30Days
      },
      demographics: {
        ageGroups,
        genderDistribution
      },
      statusDistribution
    });
  } catch (error) {
    logger.error('Error fetching patient metrics:', error);
    next(new InternalServerError('Failed to fetch patient metrics'));
  }
}));

/**
 * @route GET /api/dashboard/appointment-metrics
 * @desc Get appointment tracking metrics
 * @access Admin
 */
router.get('/appointment-metrics', asyncHandler(async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const medicalHistoryRepo = getMedicalHistoryRepository();
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    const sevenDaysFromNow = new Date(today);
    sevenDaysFromNow.setDate(sevenDaysFromNow.getDate() + 7);
    
    const todaysAppointments = await medicalHistoryRepo.count({
      where: {
        date: Between(today, tomorrow)
      },
      cache: {
        id: 'dashboard:appointmentMetrics:todaysAppointments',
        milliseconds: 300000
      }
    });
    
    const upcomingAppointments = await medicalHistoryRepo.count({
      where: {
        date: Between(today, sevenDaysFromNow)
      },
      cache: {
        id: 'dashboard:appointmentMetrics:upcomingAppointments',
        milliseconds: 300000
      }
    });
    
    // Get all medical histories as a proxy for appointments
    const totalMedicalHistories = await medicalHistoryRepo.count({
      cache: {
        id: 'dashboard:appointmentMetrics:totalMedicalHistories',
        milliseconds: 300000
      }
    });
    
    // For clinician workload, we don't have clinician information in medical history
    // We'll return empty data for now
    const clinicianWorkload: Record<string, number> = {};
    
    res.json({
      todaysAppointments,
      upcomingAppointments,
      completionRate: totalMedicalHistories > 0 ? 100 : 0, // All medical histories are "completed"
      noShowRate: 0, // We don't track this
      clinicianWorkload
    });
  } catch (error) {
    logger.error('Error fetching appointment metrics:', error);
    next(new InternalServerError('Failed to fetch appointment metrics'));
  }
}));

/**
 * @route GET /api/dashboard/system-metrics
 * @desc Get system health metrics
 * @access Admin
 */
router.get('/system-metrics', asyncHandler(async (_req: Request, res: Response, next: NextFunction) => {
  try {
    const dbHealth = AppDataSource.isInitialized ? 'healthy' : 'unhealthy';
    
    const uptime = process.uptime();
    
    // For API performance and error rates, we don't have real-time monitoring
    // In a production system, this would integrate with monitoring tools
    const apiMetrics = {
      avgResponseTime: 0, // Placeholder
      p95ResponseTime: 0, // Placeholder
      errorRate: 0 // Placeholder
    };
    
    res.json({
      uptime: Math.floor(uptime),
      databaseHealth: dbHealth,
      apiPerformance: apiMetrics
    });
  } catch (error) {
    logger.error('Error fetching system metrics:', error);
    next(new InternalServerError('Failed to fetch system metrics'));
  }
}));

export default router;