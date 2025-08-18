import { apiRequest } from './apiRequest';
import type { Patient, PatientFormData } from '../types/patient';
import { useQuery } from '@tanstack/react-query';

const API_BASE_URL = `${import.meta.env.VITE_API_BASE_URL}/api/patients`;

export interface PaginatedResponse {
  data: Patient[];
  pagination: {
    total: number;
    page: number;
    pageSize: number;
    totalPages: number;
  };
}

export interface SortState {
  field: keyof Patient;
  direction: 'asc' | 'desc';
}

export const PatientService = {
  usePatients: (page: number = 1, pageSize: number = 10, filters: Record<string, string> = {}, sort: SortState = { field: 'lastName', direction: 'asc' }) => useQuery<PaginatedResponse>({
    queryKey: ['patients', page, pageSize, filters, sort],
    queryFn: async () => {
      const params = new URLSearchParams({
        page: page.toString(),
        pageSize: pageSize.toString(),
        sort: sort.field,
        order: sort.direction,
        ...filters
      });
      return apiRequest<PaginatedResponse>('GET', `${API_BASE_URL}?${params.toString()}`);
    }
  }),

  usePatient: (id: string, options?: { enabled?: boolean }) => useQuery<Patient>({
    queryKey: ['patient', id],
    queryFn: async () => {
      const endpoint = id === 'me'
        ? `${API_BASE_URL}/me`
        : `${API_BASE_URL}/${id}`;
      
      try {
        return await apiRequest<Patient>('GET', endpoint);
      } catch (error) {
        console.error('Error fetching patient:', error);
        throw error;
      }
    },
    ...options
  }),

  async getPatientById(id: string): Promise<Patient> {
    const endpoint = id === 'me'
      ? `${API_BASE_URL}/me`
      : `${API_BASE_URL}/${id}`;
    return apiRequest<Patient>('GET', endpoint);
  },

  async createPatient(data: PatientFormData) {
    return apiRequest<Patient>('POST', API_BASE_URL, data);
  },

  async updatePatient(id: string, data: PatientFormData) {
    return apiRequest<Patient>('PATCH', `${API_BASE_URL}/${id}`, data);
  },

  async deletePatient(id: string) {
    await apiRequest<void>('DELETE', `${API_BASE_URL}/${id}`);
  }
};