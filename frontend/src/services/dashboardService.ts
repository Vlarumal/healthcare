import { apiRequest } from './apiRequest';
import type { PatientMetrics, AppointmentMetrics, SystemMetrics } from '../types/dashboard';

const DASHBOARD_API_PATH = '/api/dashboard';

export const DashboardService = {
  async getPatientMetrics(): Promise<PatientMetrics> {
    try {
      return await apiRequest<PatientMetrics>('GET', `${DASHBOARD_API_PATH}/patient-metrics`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to fetch patient metrics:', error);
      }
      throw new Error('Failed to fetch patient metrics. Please try again later.');
    }
  },

  async getAppointmentMetrics(): Promise<AppointmentMetrics> {
    try {
      return await apiRequest<AppointmentMetrics>('GET', `${DASHBOARD_API_PATH}/appointment-metrics`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to fetch appointment metrics:', error);
      }
      throw new Error('Failed to fetch appointment metrics. Please try again later.');
    }
  },

  async getSystemMetrics(): Promise<SystemMetrics> {
    try {
      return await apiRequest<SystemMetrics>('GET', `${DASHBOARD_API_PATH}/system-metrics`);
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Failed to fetch system metrics:', error);
      }
      throw new Error('Failed to fetch system metrics. Please try again later.');
    }
  }
};