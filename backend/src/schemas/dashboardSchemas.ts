import { z } from 'zod';

export const PatientMetricsSchema = z.object({
  totalPatients: z.number().int().nonnegative(),
  newPatients: z.object({
    last7Days: z.number().int().nonnegative(),
    last30Days: z.number().int().nonnegative()
  }),
  demographics: z.object({
    ageGroups: z.record(z.string(), z.number().int().nonnegative()),
    genderDistribution: z.record(z.string(), z.number().int().nonnegative())
  }),
  statusDistribution: z.object({
    active: z.number().int().nonnegative(),
    discharged: z.number().int().nonnegative(),
    followUpNeeded: z.number().int().nonnegative()
  })
});

export const AppointmentMetricsSchema = z.object({
  todaysAppointments: z.number().int().nonnegative(),
  upcomingAppointments: z.number().int().nonnegative(),
  completionRate: z.number().min(0).max(100),
  noShowRate: z.number().min(0).max(100),
  clinicianWorkload: z.record(z.string(), z.number().int().nonnegative())
});

export const SystemMetricsSchema = z.object({
  uptime: z.number().int().nonnegative(),
  databaseHealth: z.enum(['healthy', 'unhealthy']),
  apiPerformance: z.object({
    avgResponseTime: z.number().nonnegative(),
    p95ResponseTime: z.number().nonnegative(),
    errorRate: z.number().min(0).max(100)
  })
});

export const ErrorSchema = z.object({
  error: z.object({
    status: z.number(),
    code: z.string(),
    message: z.string()
  })
});