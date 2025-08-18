import { z } from 'zod';

const medicalHistoryBaseSchema = z.object({
  date: z.string().refine(s => {
    const d = new Date(s);
    return !isNaN(d.getTime()) && d <= new Date();
  }, {
    message: "Invalid date format or future date"
  }),
  diagnosis: z.string().min(5).max(500),
  treatment: z.string().min(5).max(500),
  patientId: z.number().int().positive(),
  notes: z.string().nullable().optional()
});

export const MedicalHistoryCreateSchema = medicalHistoryBaseSchema;
export const MedicalHistoryUpdateSchema = medicalHistoryBaseSchema.partial();