import { useQueryClient, useMutation } from '@tanstack/react-query';
import { PatientService } from '../services/PatientService';
import type { Patient, PatientFormData } from '../types/patient';
import { useEffect, useState, useMemo, useCallback, memo } from 'react';
import { PatientForm } from './PatientForm';
import { EmptyState } from './EmptyState';
import { StandardButton } from './common/StandardButton';
import {
  Stack,
  Paper,
  Typography,
  Box,
  CircularProgress,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';
import { Edit, Delete, Visibility } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import dayjs from 'dayjs';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';
import {
  DataGrid,
  type GridColDef,
  type GridSortModel,
  type GridPaginationModel,
  GridActionsCellItem
} from '@mui/x-data-grid';
import { ErrorDisplay } from './common/ErrorDisplay';
import { PatientFilter } from './PatientFilter';

const useDeepCompareFilters = () => {
  return useCallback((obj1: Record<string, string>, obj2: Record<string, string>): boolean => {
    const keys1 = Object.keys(obj1);
    const keys2 = Object.keys(obj2);
    
    if (keys1.length !== keys2.length) return false;
    
    for (const key of keys1) {
      if (obj1[key] !== obj2[key]) return false;
    }
    
    return true;
  }, []);
};

export const PatientList = () => {
  const queryClient = useQueryClient();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedPatient, setSelectedPatient] = useState<Patient | null>(null);
  const [paginationModel, setPaginationModel] = useState({
    page: 0,
    pageSize: 10,
  });
  const [deletingIds, setDeletingIds] = useState<string[]>([]);
  const [appliedFilters, setAppliedFilters] = useState({});
  const [sortModel, setSortModel] = useState<GridSortModel>([{
    field: 'lastName',
    sort: 'asc'
  }]);
  
  const fieldMapping = useMemo(() => ({
    name: 'lastName',
    email: 'email',
    dateOfBirth: 'dateOfBirth',
    gender: 'gender',
    phoneNumber: 'phoneNumber',
    id: 'id'
  } as Record<string, keyof Patient>), []);
  
  const {
    data: response,
    isLoading,
    isError,
    error
  } = PatientService.usePatients(
    paginationModel.page + 1,
    paginationModel.pageSize,
    appliedFilters,
    {
      field: fieldMapping[sortModel[0]?.field] || 'lastName',
      direction: sortModel[0]?.sort || 'asc'
    }
  );
  
  const patients = response?.data || [];
  const pagination = response?.pagination;
  const { user, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated && user?.role === 'patient') {
      navigate('/patients/me');
    }
  }, [isAuthenticated, user, navigate]);

  const deleteMutation = useMutation<void, Error, string>({
    mutationFn: (id: string) => {
      setDeletingIds(prev => [...prev, id]);
      return PatientService.deletePatient(id);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['patients'] }),
    onSettled: (_, __, id) => {
      setDeletingIds(prev => prev.filter(deletingId => deletingId !== id));
    }
  });

  const handleSubmit = useCallback((data: PatientFormData) => {
    const operation = selectedPatient
      ? PatientService.updatePatient(selectedPatient.id, data)
      : PatientService.createPatient(data);

    operation.then(() => {
      setOpenDialog(false);
      queryClient.invalidateQueries({ queryKey: ['patients'] });
    });
  }, [selectedPatient, queryClient]);

  const deepCompareFilters = useDeepCompareFilters();

  const handleAddNewPatient = useCallback(() => {
    setSelectedPatient(null);
    setOpenDialog(true);
  }, []);

  const handlePaginationModelChange = useCallback((newModel: GridPaginationModel) => {
    setPaginationModel(newModel);
  }, []);

  const handleSortModelChange = useCallback((newSortModel: GridSortModel) => {
    setSortModel(newSortModel);
  }, []);

  const nameValueGetter = useCallback((_value: unknown, row: Patient) => `${row.firstName} ${row.lastName}`, []);
  const dobValueGetter = useCallback((_value: unknown, row: Patient) => {
    if (!row.dateOfBirth) return '';
    const date = dayjs(row.dateOfBirth);
    return date.isValid() ? date.format('MM/DD/YYYY') : row.dateOfBirth;
  }, []);

  const viewAction = user?.role !== 'patient';
  
  const ViewAction = memo(({ id }: { id: string | number }) => (
    <GridActionsCellItem
      icon={
        <Tooltip title="View patient details" arrow>
          <Visibility fontSize={isMobile ? "medium" : "small"} color='info' aria-label="View patient details" />
        </Tooltip>
      }
      onClick={() => navigate(`/patients/${id}`)}
      label="View patient details"
      showInMenu={false}
    />
  ), (prevProps, nextProps) => prevProps.id === nextProps.id);

  const EditAction = memo(({ row }: { row: Patient }) => (
    <GridActionsCellItem
      icon={
        <Tooltip title="Edit patient" arrow>
          <Edit fontSize={isMobile ? "medium" : "small"} color='warning' aria-label="Edit patient" />
        </Tooltip>
      }
      onClick={() => {
        setSelectedPatient(row);
        setOpenDialog(true);
      }}
      label="Edit patient"
      showInMenu={false}
    />
  ), (prevProps, nextProps) => prevProps.row.id === nextProps.row.id);

  const DeleteAction = memo(({ id }: { id: string | number }) => (
    <GridActionsCellItem
      icon={deletingIds.includes(id as string) ? (
        <Tooltip title="Deleting patient..." arrow>
          <CircularProgress size={isMobile ? 32 : 24} aria-label="Deleting patient" />
        </Tooltip>
      ) : (
        <Tooltip title="Delete patient" arrow>
          <Delete fontSize={isMobile ? "medium" : "small"} color='error' aria-label="Delete patient" />
        </Tooltip>
      )}
      onClick={() => deleteMutation.mutate(id as string)}
      label="Delete patient"
      showInMenu={false}
      disabled={deletingIds.includes(id as string)}
    />
  ), (prevProps, nextProps) => prevProps.id === nextProps.id &&
     deletingIds.includes(prevProps.id as string) === deletingIds.includes(nextProps.id as string));

  const mobileColumns: GridColDef<Patient>[] = useMemo(() => [
    {
      field: 'name',
      headerName: 'Full Name',
      flex: 1,
      minWidth: 120,
      valueGetter: nameValueGetter,
      sortable: true,
    },
    {
      field: 'actions',
      headerName: 'Actions',
      type: 'actions',
      flex: 1,
      minWidth: 120,
      getActions: (params) => {
        const actions = [];
        
        if (viewAction) {
          actions.push(<ViewAction id={params.id} />);
        }
        
        actions.push(<EditAction row={params.row} />);
        actions.push(<DeleteAction id={params.id} />);
        
        return actions;
      }
    }
  ], [nameValueGetter, viewAction, ViewAction, EditAction, DeleteAction]);

  const desktopColumns: GridColDef<Patient>[] = useMemo(() => [
    {
      field: 'name',
      headerName: 'Full Name',
      flex: 1,
      minWidth: 150,
      valueGetter: nameValueGetter,
      sortable: true,
    },
    {
      field: 'email',
      headerName: 'Email',
      flex: 1,
      minWidth: 200,
      sortable: true
    },
    {
      field: 'dateOfBirth',
      headerName: 'Date of Birth',
      flex: 1,
      minWidth: 150,
      valueGetter: dobValueGetter,
      sortable: true
    },
    {
      field: 'gender',
      headerName: 'Gender',
      flex: 1,
      minWidth: 120,
      sortable: true
    },
    {
      field: 'phoneNumber',
      headerName: 'Phone',
      flex: 1,
      minWidth: 150,
      sortable: true
    },
    {
      field: 'actions',
      headerName: 'Actions',
      type: 'actions',
      flex: 1,
      minWidth: 150,
      getActions: (params) => {
        const actions = [];
        
        if (viewAction) {
          actions.push(<ViewAction id={params.id} />);
        }
        
        actions.push(<EditAction row={params.row} />);
        actions.push(<DeleteAction id={params.id} />);
        
        return actions;
      }
    }
  ], [nameValueGetter, dobValueGetter, viewAction, ViewAction, EditAction, DeleteAction]);

  const columns = useMemo(() => isMobile ? mobileColumns : desktopColumns, [isMobile, mobileColumns, desktopColumns]);

  return (
    <Stack spacing={3}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h4" component="h1" sx={{ fontWeight: 600 }}>
          Patient Records
        </Typography>
        <StandardButton
          variant="contained"
          onClick={handleAddNewPatient}
          label="Add New Patient"
        />
      </Stack>

      {/* Filter Section */}
      <Paper elevation={2} sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>Search Patient(s)</Typography>
        <PatientFilter
          onApplyFilters={(newFilters) => {
            if (!deepCompareFilters(appliedFilters, newFilters)) {
              setAppliedFilters(newFilters);
              setPaginationModel(prev => ({ ...prev, page: 0 }));
            }
          }}
          onResetFilters={() => {
            if (Object.keys(appliedFilters).length > 0) {
              setAppliedFilters({});
              setPaginationModel(prev => ({ ...prev, page: 0 }));
            }
          }}
        />
      </Paper>
      
      {isError ? (
       <Box display="flex" justifyContent="center" mt={4}>
         <ErrorDisplay
           message={`Error loading patients: ${error?.message || 'Unknown error'}`}
           severity="error"
         />
       </Box>
     ) : (
       <Box sx={{
         height: isMobile ? '70vh' : 600,
         width: '100%',
         '& .MuiDataGrid-columnHeaders': {
           backgroundColor: 'primary.light',
         }
       }}>
          <DataGrid
            rows={patients}
            columns={columns}
            rowCount={pagination?.total || 0}
            loading={isLoading}
            paginationMode="server"
            sortingMode="server"
            paginationModel={paginationModel}
            onPaginationModelChange={handlePaginationModelChange}
            sortModel={sortModel}
            onSortModelChange={handleSortModelChange}
            pageSizeOptions={[5, 10, 20, 50]}
            disableRowSelectionOnClick
            getRowId={(row) => row.id}
            sx={{
              '& .MuiDataGrid-cell': {
                borderBottom: 'none',
              },
              '& .MuiDataGrid-columnHeaderTitle': {
                fontWeight: 600,
              }
            }}
          />
        </Box>
      )}
      
      {patients.length === 0 && !isLoading && !isError && (
        <EmptyState
          title="No patient records found"
          description="Create your first patient record to get started"
          actionText="Add New Patient"
          onClickAction={handleAddNewPatient}
        />
      )}

      <PatientForm
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        onSubmit={handleSubmit}
        initialData={selectedPatient ? {
          firstName: selectedPatient.firstName,
          lastName: selectedPatient.lastName,
          email: selectedPatient.email,
          dateOfBirth: selectedPatient.dateOfBirth,
          gender: selectedPatient.gender,
          phoneNumber: selectedPatient.phoneNumber,
          address: selectedPatient.address,
          city: selectedPatient.city,
          zipCode: selectedPatient.zipCode,
          role: selectedPatient.role
        } : undefined}
      />
    </Stack>
  );
};