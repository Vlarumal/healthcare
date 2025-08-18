import type { MedicalHistory, MedicalHistoryCreate, MedicalHistoryUpdate } from '../types/medicalHistory';
import { apiRequest } from './apiRequest';
import { useQuery } from '@tanstack/react-query';

const MEDICAL_HISTORY_API_PATH = '/api/medical-history';

export const MedicalHistoryService = {
  async create(history: MedicalHistoryCreate): Promise<MedicalHistory> {
    try {
      return await apiRequest('POST', MEDICAL_HISTORY_API_PATH, history);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to create medical history:', error);
      }
      throw new Error('Failed to create medical history record. Please try again.');
    }
  },

  async getByPatient(patientId: string): Promise<MedicalHistory[]> {
    try {
      return await apiRequest('GET', `${MEDICAL_HISTORY_API_PATH}/patient/${patientId}`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error(`Failed to get medical histories for patient ${patientId}:`, error);
      }
      throw new Error('Failed to fetch medical histories. Please try again later.');
    }
  },

  async update(id: number, update: MedicalHistoryUpdate): Promise<MedicalHistory> {
    try {
      return await apiRequest('PUT', `${MEDICAL_HISTORY_API_PATH}/${id}`, update);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error(`Failed to update medical history ${id}:`, error);
      }
      throw new Error('Failed to update medical history record. Please try again.');
    }
  },

  async delete(id: number): Promise<void> {
    try {
      return await apiRequest('DELETE', `${MEDICAL_HISTORY_API_PATH}/${id}`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error(`Failed to delete medical history ${id}:`, error);
      }
      throw new Error('Failed to delete medical history record. Please try again.');
    }
  },

  useMedicalHistoriesByPatientId(patientId: string, isAuthorized: boolean = true) {
    return useQuery<MedicalHistory[], Error>({
      queryKey: ['medicalHistories', patientId],
      queryFn: async () => {
        if (!isAuthorized) {
          throw new Error('Unauthorized access to medical history');
        }
        const response = await MedicalHistoryService.getByPatient(patientId);
        return response;
      },
      enabled: !!patientId && isAuthorized,
    });
  },
};