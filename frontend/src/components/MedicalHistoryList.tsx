import { useMemo, useCallback, useEffect } from 'react';
import {
  DataGrid,
  GridActionsCellItem,
  type GridColDef,
  type GridRowId,
} from '@mui/x-data-grid';
import { Delete, Edit } from '@mui/icons-material';
import { Box, CircularProgress, Tooltip, Card, CardContent, Typography, Stack, useTheme } from '@mui/material';
import useMediaQuery from '@mui/material/useMediaQuery';
import type { MedicalHistory } from '../types/medicalHistory';
import { sanitizeMedicalHistory } from '../utils/sanitization';

interface MedicalHistoryListProps {
  patientId: string;
  histories: MedicalHistory[];
  deletingIds: number[];
  onEdit: (history: MedicalHistory) => void;
  onDelete: (id: number) => void;
  onDeletingIdsChange?: (newDeletingIds: number[]) => void;
}

export const MedicalHistoryList = ({
  histories,
  deletingIds,
  onEdit,
  onDelete,
  onDeletingIdsChange,
}: MedicalHistoryListProps) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  
  useEffect(() => {
    if (onDeletingIdsChange && deletingIds.length > 0) {
      const validDeletingIds = deletingIds.filter(id =>
        histories.some(history => history.id === id)
      );
      
      if (validDeletingIds.length !== deletingIds.length) {
        onDeletingIdsChange(validDeletingIds);
      }
    }
  }, [histories, deletingIds, onDeletingIdsChange]);

  const handleDelete = useCallback(
    (id: GridRowId) => {
      onDelete(id as number);
    },
    [onDelete]
  );

  const EditAction = useCallback(
    ({ row }: { row: MedicalHistory }) => (
      <Tooltip title='Edit' key={`edit-${row.id}`}>
        <span>
          <GridActionsCellItem
            icon={<Edit color='warning' />}
            label='Edit'
            onClick={() => onEdit(row)}
            disabled={deletingIds.includes(row.id)}
          />
        </span>
      </Tooltip>
    ),
    [onEdit, deletingIds]
  );

  const DeleteAction = useCallback(
    ({ id }: { id: GridRowId }) => {
      const isDeleting = deletingIds.includes(id as number);
      return (
        <Tooltip title='Delete' key={`delete-${id}`}>
          <span>
            <GridActionsCellItem
              icon={
                isDeleting ? (
                  <CircularProgress size={24} />
                ) : (
                  <Delete color='error' />
                )
              }
              label='Delete'
              onClick={() => handleDelete(id)}
              disabled={isDeleting}
            />
          </span>
        </Tooltip>
      );
    },
    [deletingIds, handleDelete]
  );

  const columns: GridColDef<MedicalHistory>[] = useMemo(
    () => [
      {
        field: 'date',
        headerName: 'Date',
        flex: 1,
        minWidth: 80,
      },
      {
        field: 'diagnosis',
        headerName: 'Diagnosis',
        flex: 1.5,
        minWidth: 120,
        valueGetter: (value) => sanitizeMedicalHistory(value),
      },
      {
        field: 'treatment',
        headerName: 'Treatment',
        flex: 1.5,
        minWidth: 120,
        hideable: true,
        resizable: true,
        valueGetter: (value) => sanitizeMedicalHistory(value),
      },
      {
        field: 'notes',
        headerName: 'Notes',
        flex: 2,
        minWidth: 150,
        renderCell: (params) => (
          <Box
            sx={{
              whiteSpace: 'pre-wrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              maxHeight: 100,
              display: '-webkit-box',
              WebkitLineClamp: 4,
              WebkitBoxOrient: 'vertical',
            }}
            dangerouslySetInnerHTML={{ __html: sanitizeMedicalHistory(params.value || 'None') }}
          />
        ),
      },
      {
        field: 'actions',
        type: 'actions',
        headerName: 'Actions',
        width: 100,
        getActions: (params) => {
          return [
            <EditAction row={params.row} />,
            <DeleteAction id={params.id} />,
          ];
        },
      },
    ],
    [EditAction, DeleteAction]
  );

  const MobileCardView = useCallback(
    ({ history }: { history: MedicalHistory }) => (
      <Card
        variant="outlined"
        sx={{
          mb: 2,
          '&:last-child': { mb: 0 }
        }}
      >
        <CardContent>
          <Stack spacing={1}>
            <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
              <Typography variant="h6" component="h3">
                {history.date}
              </Typography>
              <Stack direction="row" spacing={1}>
                <Tooltip title="Edit">
                  <span>
                    <Edit
                      color="warning"
                      onClick={() => onEdit(history)}
                      style={{ cursor: 'pointer' }}
                    />
                  </span>
                </Tooltip>
                {deletingIds.includes(history.id) ? (
                  <CircularProgress size={24} />
                ) : (
                  <Tooltip title="Delete">
                    <span>
                      <Delete
                        color="error"
                        onClick={() => handleDelete(history.id)}
                        style={{ cursor: 'pointer' }}
                      />
                    </span>
                  </Tooltip>
                )}
              </Stack>
            </Stack>
            <Typography variant="subtitle1" color="text.secondary">
              <strong>Diagnosis:</strong> <span dangerouslySetInnerHTML={{ __html: sanitizeMedicalHistory(history.diagnosis) }} />
            </Typography>
            <Typography variant="body2">
              <strong>Treatment:</strong> <span dangerouslySetInnerHTML={{ __html: sanitizeMedicalHistory(history.treatment) }} />
            </Typography>
            <Typography variant="body2">
              <strong>Notes:</strong> <span dangerouslySetInnerHTML={{ __html: sanitizeMedicalHistory(history.notes || 'None') }} />
            </Typography>
          </Stack>
        </CardContent>
      </Card>
    ),
    [onEdit, handleDelete, deletingIds]
  );

  return (
    <Box sx={{ width: '100%' }}>
      {isMobile ? (
        <Box sx={{ maxHeight: '600px', overflowY: 'auto' }}>
          {histories.map((history) => (
            <MobileCardView key={history.id} history={history} />
          ))}
        </Box>
      ) : (
        <Box
          sx={{
            height: { xs: 300, sm: 400, md: 500, lg: 600 },
            width: '100%',
          }}
        >
          <DataGrid
            rows={histories}
            columns={columns}
            getRowId={(row) => row.id}
            disableColumnMenu
            density='compact'
            sx={{
              '& .MuiDataGrid-cell': {
                wordBreak: 'break-word',
              },
              '& .MuiDataGrid-columnHeaderTitle': {
                whiteSpace: 'normal',
                lineHeight: '1.2rem',
              },
            }}
          />
        </Box>
      )}
    </Box>
  );
};
