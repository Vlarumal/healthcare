import { MedicalHistoryList } from '../MedicalHistoryList';
import type { MedicalHistory } from '../../types/medicalHistory';
import { Add as AddIcon } from '@mui/icons-material';
import { DetailSection } from '../common/DetailSection';
import { LoadingStateHandler } from '../common/LoadingStateHandler';
import { ErrorDisplay } from '../common/ErrorDisplay';
import { Button } from '@mui/material';

interface MedicalHistorySectionProps {
  patientId: string;
  medicalHistories: MedicalHistory[];
  isMedicalHistoriesLoading: boolean;
  isMedicalHistoriesError: boolean;
  onEdit: (history: MedicalHistory) => void;
  onDelete: (id: number) => void;
  onAdd: () => void;
  canEdit: boolean;
}

export const MedicalHistorySection = ({
  patientId,
  medicalHistories,
  isMedicalHistoriesLoading,
  isMedicalHistoriesError,
  onEdit,
  onDelete,
  onAdd,
  canEdit,
}: MedicalHistorySectionProps) => {
  return (
    <DetailSection
      title="Medical History"
      headerActions={
        canEdit ? (
          <Button
            variant="contained"
            color="primary"
            onClick={onAdd}
            startIcon={<AddIcon />}
          >
            Add New Entry
          </Button>
        ) : null
      }
    >
      {isMedicalHistoriesLoading ? (
        <LoadingStateHandler count={3} />
      ) : isMedicalHistoriesError ? (
        <ErrorDisplay
          message="Failed to load medical history records. Please check your connection and try again."
          severity="error"
        />
      ) : medicalHistories && medicalHistories.length > 0 ? (
        <MedicalHistoryList
          patientId={patientId}
          histories={medicalHistories}
          onEdit={onEdit}
          onDelete={onDelete}
        />
      ) : (
        <ErrorDisplay
          message="No medical history records found for this patient."
          severity="info"
        />
      )}
    </DetailSection>
  );
};