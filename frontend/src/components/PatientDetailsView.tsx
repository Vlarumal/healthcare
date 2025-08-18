import { useParams, useNavigate } from 'react-router-dom';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PatientService } from '../services/PatientService';
import { Box, Paper, Grid } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { useEffect, useCallback, useState, useMemo } from 'react';
import { MedicalHistoryService } from '../services';
import { PatientHeader } from './PatientDetailsView/PatientHeader';
import { DetailItem } from './common/DetailItem';
import { MedicalHistorySection } from './PatientDetailsView/MedicalHistorySection';
import { ErrorDisplay } from './common/ErrorDisplay';
import { LoadingStateHandler } from './common/LoadingStateHandler';
import { DetailSection } from './common/DetailSection';
import { BackButton } from './common/BackButton';
import { MedicalHistoryForm } from './MedicalHistoryForm';
import { PatientForm } from './PatientForm';
import dayjs from 'dayjs';
import type { MedicalHistory } from '../types/medicalHistory';
import type { PatientFormData } from '../types/patient';

export const PatientDetailsView = () => {
  const { isAuthenticated, user } = useAuth();
  const { id: idParam } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const patientId = useMemo(() => {
    return idParam === 'me' && user
      ? user.id.toString()
      : idParam || '';
  }, [idParam, user]);

  // Remove debug logging in production
  // useEffect(() => {
  //   if (import.meta.env.DEV) {
  //     console.log(`Patient ID from URL: ${idParam}`);
  //     console.log(`Computed patientId: ${patientId}`);
  //     console.log(`User: ${user ? JSON.stringify(user) : 'null'}`);
  //   }
  // }, [idParam, patientId, user]);

  const handleBack = useCallback(() => {
    navigate('/');
  }, [navigate]);

  useEffect(() => {
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handleBack();
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => {
      window.removeEventListener('keydown', handleEsc);
    };
  }, [handleBack]);

  const [editingHistory, setEditingHistory] =
    useState<MedicalHistory | null>(null);
  const [isAddingHistory, setIsAddingHistory] = useState(false);

  const [isEditingPatient, setIsEditingPatient] = useState(false);

  const [error, setError] = useState<string | null>(null);

  const handleEdit = useCallback((history: MedicalHistory) => {
    setEditingHistory(history);
  }, []);

  const handleAdd = useCallback(() => {
    setIsAddingHistory(true);
  }, []);

  const handleDelete = useCallback(
    async (id: number) => {
      if (
        window.confirm(
          'Are you sure you want to delete this medical history entry?'
        )
      ) {
        try {
          await MedicalHistoryService.delete(id);
          queryClient.invalidateQueries({
            queryKey: ['medicalHistories', patientId],
          });
        } catch (error) {
          let errorMessage =
            'Failed to delete medical history entry. Please try again.';
          if (error instanceof Error) {
            errorMessage = error.message;
          }
          setError(errorMessage);
        }
      }
    },
    [patientId, queryClient]
  );

  const handleFormSuccess = useCallback(() => {
    setEditingHistory(null);
    setIsAddingHistory(false);
    queryClient.invalidateQueries({
      queryKey: ['medicalHistories', patientId],
    });
  }, [patientId, queryClient]);

  const handlePatientEdit = useCallback(() => {
    setIsEditingPatient(true);
  }, []);

  // Patient update mutation with optimistic updates
  const updateMutation = useMutation({
    mutationFn: (data: PatientFormData) => {
      if (!patientId) {
        throw new Error('Patient ID is missing');
      }
      return PatientService.updatePatient(patientId, data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ['patient', patientId],
      });
      queryClient.invalidateQueries({ queryKey: ['patients'] });
      setIsEditingPatient(false);
    },
    onError: (err: unknown) => {
      let errorDetails = 'Unknown error';
      if (err instanceof Error) {
        errorDetails = err.message;
        interface AxiosError {
          response?: {
            data: unknown;
          };
        }
        const axiosError = err as AxiosError;
        if (axiosError.response?.data) {
          errorDetails = JSON.stringify(axiosError.response.data);
        }
      } else if (typeof err === 'string') {
        errorDetails = err;
      }

      setError(errorDetails);
    },
  });

  const handlePatientSubmit = useCallback(
    (data: PatientFormData) => {
      if (!patientId) {
        setError('Patient ID is missing');
        return;
      }

      // Remove id from form data since it comes from URL parameter
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { id: __, ...formData } = data;

      const submissionData = {
        ...formData,
        phoneNumber: formData.phoneNumber === '' ? null : formData.phoneNumber,
      };
      updateMutation.mutate(submissionData);
    },
    [patientId, updateMutation]
  );

  const {
    data: patientData,
    isLoading: patientLoading,
    isError: patientError,
    error: patientQueryError,
  } = PatientService.usePatient(patientId, {
    enabled: (!!patientId || !!user?.id) && isAuthenticated,
  });

  const patientFormInitialData = useMemo(() => {
    if (!patientData) return undefined;
    return {
      firstName: patientData.firstName,
      lastName: patientData.lastName,
      email: patientData.email,
      dateOfBirth: patientData.dateOfBirth
        ? dayjs(patientData.dateOfBirth).format('YYYY-MM-DD')
        : '',
      gender: patientData.gender,
      phoneNumber: patientData.phoneNumber,
      address: patientData.address,
      city: patientData.city,
      zipCode: patientData.zipCode,
      role: patientData.role,
    };
  }, [patientData]);

  const {
    data: medicalHistories,
    isLoading: isMedicalHistoriesLoading,
    isError: isMedicalHistoriesError,
    error: medicalHistoryError,
  } = MedicalHistoryService.useMedicalHistoriesByPatientId(
    patientId,
    isAuthenticated && !!patientId
  );

  // Debug: Log patient data when received
  // useEffect(() => {
  //   if (patientData) {
  //     console.log('Patient data received:', patientData);
  //   }
  // }, [patientData]);

  if (!isAuthenticated || !user) {
    return (
      <Box mt={4}>
        <ErrorDisplay
          message='You must be logged in to view patient details.'
          severity='error'
          sx={{ maxWidth: 600, mx: 'auto' }}
        />
        <Box
          sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}
        >
          <BackButton
            variant='outlined'
            label='Go Back'
          />
        </Box>
      </Box>
    );
  }

  const canEdit = user && ['clinician', 'admin'].includes(user.role);

  if (patientLoading) {
    return (
      <Box
        display='flex'
        justifyContent='center'
        mt={4}
      >
        <LoadingStateHandler count={3} />
      </Box>
    );
  }

  if (patientError) {
    if (patientQueryError?.name === '404') {
      return (
        <Box mt={4}>
          <ErrorDisplay
            message='Patient record not found. Please contact support.'
            severity='error'
            sx={{ maxWidth: 600, mx: 'auto' }}
          />
        </Box>
      );
    } else if (patientId === 'me' && !user) {
      return (
        <Box mt={4}>
          <ErrorDisplay
            message='You must be logged in to view your patient record.'
            severity='error'
            sx={{ maxWidth: 600, mx: 'auto' }}
          />
        </Box>
      );
    }

    return (
      <Box mt={4}>
        <ErrorDisplay
          message='Failed to load patient details. Please try again later.'
          severity='error'
          sx={{ maxWidth: 600, mx: 'auto' }}
        />
      </Box>
    );
  } else if (!patientData && !patientLoading) {
    return (
      <Box mt={4}>
        <ErrorDisplay
          message='No patient data available. Please try again later.'
          severity='error'
          sx={{ maxWidth: 600, mx: 'auto' }}
        />
      </Box>
    );
  }

  if (!patientData) {
    return (
      <Box mt={4}>
        <ErrorDisplay
          message='Patient data is not available'
          severity='error'
          sx={{ maxWidth: 600, mx: 'auto' }}
        />
      </Box>
    );
  }

  return (
    <Box>
      {['clinician', 'admin', 'staff'].includes(user.role) && (
        <BackButton
          variant='contained'
          color='primary'
          label='Back to Patient List'
          sx={{ mb: 2 }}
        />
      )}
      <Paper
        elevation={2}
        sx={{
          p: 3,
          mb: 3,
          borderRadius: 2,
        }}
      >
        <Box
          sx={{
            display: 'flex',
            flexDirection: { xs: 'column', sm: 'column', md: 'row' },
            gap: { xs: 2, sm: 3, md: 4 },
          }}
        >
          <PatientHeader
            firstName={patientData.firstName}
            lastName={patientData.lastName}
            onEdit={handlePatientEdit}
            canEdit={canEdit}
          />

          <Box sx={{ flex: 2 }}>
            <DetailSection title='Patient Information'>
              <Grid
                container
                spacing={{ xs: 2, md: 3 }}
                rowSpacing={2}
                columnSpacing={3}
                sx={{ mb: 4 }}
              >
                {canEdit && (
                  <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                    <DetailItem
                      label='Patient ID'
                      value={
                        patientData.id
                          ? patientData.id.toString()
                          : ''
                      }
                    />
                  </Grid>
                )}
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Email'
                    value={patientData.email}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Phone'
                    value={patientData.phoneNumber || '-'}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Date of Birth'
                    value={
                      patientData.dateOfBirth
                        ? dayjs(patientData.dateOfBirth).format(
                            'MM/DD/YYYY'
                          )
                        : '-'
                    }
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Gender'
                    value={
                      patientData.gender
                        ? patientData.gender.charAt(0).toUpperCase() +
                          patientData.gender.slice(1)
                        : '-'
                    }
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Address'
                    value={patientData.address || '-'}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='City'
                    value={patientData.city || '-'}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Zip Code'
                    value={patientData.zipCode || '-'}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 6, md: 4 }}>
                  <DetailItem
                    label='Role'
                    value={
                      patientData.role
                        ? patientData.role.charAt(0).toUpperCase() +
                          patientData.role.slice(1)
                        : '-'
                    }
                  />
                </Grid>
              </Grid>
            </DetailSection>

            <MedicalHistorySection
              patientId={patientData.id}
              medicalHistories={medicalHistories || []}
              isMedicalHistoriesLoading={isMedicalHistoriesLoading}
              isMedicalHistoriesError={isMedicalHistoriesError}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onAdd={handleAdd}
              canEdit={canEdit}
            />

            {medicalHistoryError && (
              <ErrorDisplay
                message={medicalHistoryError.message}
                severity='error'
                sx={{ mb: 2 }}
              />
            )}

            {(editingHistory || isAddingHistory) && (
              <MedicalHistoryForm
                patientId={patientData.id}
                existingHistory={editingHistory || undefined}
                onSuccess={handleFormSuccess}
                onCancel={() => {
                  setEditingHistory(null);
                  setIsAddingHistory(false);
                }}
              />
            )}

            {error && (
              <ErrorDisplay
                message={error}
                onClose={() => setError(null)}
                sx={{ mb: 2 }}
              />
            )}

            {isEditingPatient && (
              <PatientForm
                open={isEditingPatient}
                onClose={() => {
                  setIsEditingPatient(false);
                  setError(null);
                }}
                onSubmit={handlePatientSubmit}
                initialData={patientFormInitialData}
                isSubmitting={updateMutation.isPending}
                key={patientData.id}
              />
            )}
          </Box>
        </Box>
      </Paper>
    </Box>
  );
};
