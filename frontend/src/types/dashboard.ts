export interface PatientMetrics {
  totalPatients: number;
  newPatients: {
    last7Days: number;
    last30Days: number;
  };
  demographics: {
    ageGroups: Record<string, number>;
    genderDistribution: Record<string, number>;
  };
  statusDistribution: {
    active: number;
    discharged: number;
    followUpNeeded: number;
  };
}

export interface AppointmentMetrics {
  todaysAppointments: number;
  upcomingAppointments: number;
  completionRate: number;
  noShowRate: number;
  clinicianWorkload: Record<string, number>;
}

export interface SystemMetrics {
  uptime: number;
  databaseHealth: 'healthy' | 'unhealthy';
  apiPerformance: {
    avgResponseTime: number;
    p95ResponseTime: number;
    errorRate: number;
  };
}