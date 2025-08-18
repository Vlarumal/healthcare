export interface MedicalHistory {
  id: number;
  date: string;
  diagnosis: string;
  treatment: string;
  notes?: string | null;
  patientId: number;
  createdAt: string;
  updatedAt: string;
}

export type MedicalHistoryCreate = Omit<MedicalHistory, 'id' | 'createdAt' | 'updatedAt'>;
export type MedicalHistoryUpdate = Partial<MedicalHistoryCreate>;