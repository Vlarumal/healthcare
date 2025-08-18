import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Container,
  Grid,
  Typography,
  CircularProgress,
  Alert,
  AlertTitle,
  Button
} from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { DashboardService } from '../services/dashboardService';
import type { PatientMetrics, AppointmentMetrics, SystemMetrics } from '../types/dashboard';
import { BreadcrumbNavigation } from '../components/common/BreadcrumbNavigation';
import { BackButton } from '../components/common/BackButton';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import { isAxiosErrorWithCode } from '../utils/errorUtils';
import { ERROR_CODES } from '../constants/errors';

const QuickAccessSidebar = React.lazy(() => import('../components/common/QuickAccessSidebar').then(module => ({ default: module.QuickAccessSidebar })));

const PatientStatsCard: React.FC<{ data?: PatientMetrics; loading: boolean; error?: Error }> = ({ data, loading, error }) => {
  if (loading) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="Patient Statistics Loading">
        <CardContent sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
          <CircularProgress aria-label="Loading patient statistics" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="Patient Statistics Error">
        <CardContent>
          <Alert severity="error" role="alert">
            <AlertTitle>Error Loading Patient Stats</AlertTitle>
            {error.message}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: '100%' }} role="region" aria-labelledby="patient-stats-title">
      <CardContent>
        <Typography id="patient-stats-title" variant="h6" component="h2" gutterBottom>
          Patient Statistics
        </Typography>
        {data && (
          <Box>
            <Typography variant="h4" component="p" gutterBottom>
              {data.totalPatients}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Total Patients
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom id="new-patients-heading">
                New Patients
              </Typography>
              <Typography variant="body2" aria-describedby="new-patients-heading">
                Last 7 days: {data.newPatients.last7Days}
              </Typography>
              <Typography variant="body2" aria-describedby="new-patients-heading">
                Last 30 days: {data.newPatients.last30Days}
              </Typography>
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

const AppointmentCard: React.FC<{ data?: AppointmentMetrics; loading: boolean; error?: Error }> = ({ data, loading, error }) => {
  if (loading) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="Appointments Loading">
        <CardContent sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
          <CircularProgress aria-label="Loading appointments" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="Appointments Error">
        <CardContent>
          <Alert severity="error" role="alert">
            <AlertTitle>Error Loading Appointments</AlertTitle>
            {error.message}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: '100%' }} role="region" aria-labelledby="appointment-title">
      <CardContent>
        <Typography id="appointment-title" variant="h6" component="h2" gutterBottom>
          Appointments
        </Typography>
        {data && (
          <Box>
            <Typography variant="h4" component="p" gutterBottom>
              {data.todaysAppointments}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Today's Appointments
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom id="upcoming-appointments-heading">
                Upcoming
              </Typography>
              <Typography variant="body2" aria-describedby="upcoming-appointments-heading">
                Next 7 days: {data.upcomingAppointments}
              </Typography>
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

const SystemHealthCard: React.FC<{ data?: SystemMetrics; loading: boolean; error?: Error }> = ({ data, loading, error }) => {
  if (loading) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="System Health Loading">
        <CardContent sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100%' }}>
          <CircularProgress aria-label="Loading system health" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card sx={{ height: '100%' }} role="region" aria-label="System Health Error">
        <CardContent>
          <Alert severity="error" role="alert">
            <AlertTitle>Error Loading System Health</AlertTitle>
            {error.message}
          </Alert>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card sx={{ height: '100%' }} role="region" aria-labelledby="system-health-title">
      <CardContent>
        <Typography id="system-health-title" variant="h6" component="h2" gutterBottom>
          System Health
        </Typography>
        {data && (
          <Box>
            <Typography variant="h4" component="p" gutterBottom>
              {data.databaseHealth === 'healthy' ? 'Healthy' : 'Issues Detected'}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Database Status
            </Typography>
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom id="uptime-heading">
                Uptime
              </Typography>
              <Typography variant="body2" aria-describedby="uptime-heading">
                {Math.floor(data.uptime / 3600)}h {Math.floor((data.uptime % 3600) / 60)}m
              </Typography>
            </Box>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export function DashboardPage() {
  const { user, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  
  // Redirect non-authenticated users to login
  React.useEffect(() => {
    if (!isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, navigate]);
  
  // Redirect non-admin users to appropriate page
  React.useEffect(() => {
    if (isAuthenticated && user?.role !== 'admin') {
      if (user?.role === 'patient') {
        navigate('/patients/me');
      } else {
        navigate('/');
      }
    }
  }, [isAuthenticated, user, navigate]);

  // Fetch all dashboard metrics
  const {
    data: patientData,
    isLoading: patientLoading,
    error: patientError,
    refetch: refetchPatientData
  } = useQuery<PatientMetrics>({
    queryKey: ['patientMetrics'],
    queryFn: DashboardService.getPatientMetrics,
    enabled: isAuthenticated && user?.role === 'admin',
    retry: (failureCount, error) => {
      // Don't retry on 403 errors
      if (isAxiosErrorWithCode(error, ERROR_CODES.PERMISSION_DENIED)) {
        return false;
      }
      return failureCount < 3;
    }
  });
  
  const {
    data: appointmentData,
    isLoading: appointmentLoading,
    error: appointmentError,
    refetch: refetchAppointmentData
  } = useQuery<AppointmentMetrics>({
    queryKey: ['appointmentMetrics'],
    queryFn: DashboardService.getAppointmentMetrics,
    enabled: isAuthenticated && user?.role === 'admin',
    retry: (failureCount, error) => {
      // Don't retry on 403 errors
      if (isAxiosErrorWithCode(error, ERROR_CODES.PERMISSION_DENIED)) {
        return false;
      }
      return failureCount < 3;
    }
  });
  
  const {
    data: systemData,
    isLoading: systemLoading,
    error: systemError,
    refetch: refetchSystemData
  } = useQuery<SystemMetrics>({
    queryKey: ['systemMetrics'],
    queryFn: DashboardService.getSystemMetrics,
    enabled: isAuthenticated && user?.role === 'admin',
    retry: (failureCount, error) => {
      // Don't retry on 403 errors
      if (isAxiosErrorWithCode(error, ERROR_CODES.PERMISSION_DENIED)) {
        return false;
      }
      return failureCount < 3;
    }
  });

  // Handle retry for all data
  const handleRetry = () => {
    refetchPatientData();
    refetchAppointmentData();
    refetchSystemData();
  };

  // Show access denied message for non-admin users
  if (isAuthenticated && user?.role !== 'admin') {
    return (
      <Box sx={{ display: 'flex' }}>
        <React.Suspense fallback={<div />}>
          <QuickAccessSidebar />
        </React.Suspense>
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            py: 4,
            width: { sm: `calc(100% - 240px)` },
            ml: { sm: '240px' }
          }}
          id="main-content"
          role="main"
        >
          <Container maxWidth="xl">
            <Box sx={{ mb: 3 }}>
              <BackButton
                to="/"
                label="Back to Patient List"
                variant="outlined"
                sx={{ mb: 2 }}
              />
              <BreadcrumbNavigation
                items={[
                  { label: 'Home', path: '/' },
                  { label: 'Dashboard' }
                ]}
              />
              <Typography
                variant="h4"
                component="h1"
                gutterBottom
                id="dashboard-title"
                sx={{
                  fontSize: {
                    xs: '1.75rem',
                    sm: '2rem',
                    md: '2.125rem'
                  }
                }}
              >
                Access Denied
              </Typography>
            </Box>
            <Alert severity="error">
              <AlertTitle>Access Denied</AlertTitle>
              You do not have permission to access the dashboard. Only administrators can view this page.
              <Box sx={{ mt: 2 }}>
                <Button
                  variant="contained"
                  onClick={() => navigate(user?.role === 'patient' ? '/patients/me' : '/')}
                >
                  Go to Home Page
                </Button>
              </Box>
            </Alert>
          </Container>
        </Box>
      </Box>
    );
  }

  // Show loading state while checking authentication
  if (!isAuthenticated || !user) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '50vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex' }}>
      <React.Suspense fallback={<div />}>
        <QuickAccessSidebar />
      </React.Suspense>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          py: 4,
          width: { sm: `calc(100% - 240px)` },
          ml: { sm: '240px' }
        }}
        id="main-content"
        role="main"
      >
        <Container maxWidth="xl">
          <Box sx={{ mb: 3 }}>
            <BackButton
              to="/"
              label="Back to Patient List"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            <BreadcrumbNavigation
              items={[
                { label: 'Home', path: '/' },
                { label: 'Dashboard' }
              ]}
            />
            <Typography
              variant="h4"
              component="h1"
              gutterBottom
              id="dashboard-title"
              sx={{
                fontSize: {
                  xs: '1.75rem',
                  sm: '2rem',
                  md: '2.125rem'
                }
              }}
            >
              Dashboard
            </Typography>
            <Typography variant="subtitle1" color="text.secondary">
              Healthcare Management System Overview
            </Typography>
          </Box>
          
          {/* Error handling with retry */}
          {(patientError || appointmentError || systemError) && (
            <Box sx={{ mb: 3 }}>
              <Alert
                severity="error"
                action={
                  <Button
                    color="inherit"
                    size="small"
                    onClick={handleRetry}
                  >
                    RETRY
                  </Button>
                }
              >
                <AlertTitle>Error Loading Dashboard</AlertTitle>
                {isAxiosErrorWithCode(patientError, ERROR_CODES.PERMISSION_DENIED) ||
                 isAxiosErrorWithCode(appointmentError, ERROR_CODES.PERMISSION_DENIED) ||
                 isAxiosErrorWithCode(systemError, ERROR_CODES.PERMISSION_DENIED) ? (
                  "You don't have permission to access dashboard data."
                ) : (
                  "Failed to load dashboard data. Please try again."
                )}
              </Alert>
            </Box>
          )}
          
          <Grid container spacing={3} aria-label="Dashboard metrics">
            <Grid size={{ xs: 12, md: 4 }}>
              <PatientStatsCard
                data={patientData}
                loading={patientLoading}
                error={patientError instanceof Error ? patientError : undefined}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <AppointmentCard
                data={appointmentData}
                loading={appointmentLoading}
                error={appointmentError instanceof Error ? appointmentError : undefined}
              />
            </Grid>
            <Grid size={{ xs: 12, md: 4 }}>
              <SystemHealthCard
                data={systemData}
                loading={systemLoading}
                error={systemError instanceof Error ? systemError : undefined}
              />
            </Grid>
          </Grid>
        </Container>
      </Box>
    </Box>
  );
}