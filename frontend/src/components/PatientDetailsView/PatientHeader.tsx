import { Box, Typography, Avatar, Chip } from '@mui/material';
import { layoutStyles, patientHeaderStyles } from '../../theme/variables';
import { StandardButton } from '../common/StandardButton';

interface PatientHeaderProps {
  firstName: string;
  lastName: string;
  onEdit?: () => void;
  canEdit?: boolean;
}

export const PatientHeader = ({ firstName, lastName, onEdit, canEdit }: PatientHeaderProps) => (
  <Box sx={layoutStyles.headerStyle}>
    <Avatar
      sx={patientHeaderStyles.avatar}
      aria-label="Patient profile"
    >
      {firstName?.charAt(0) || ''}
      {lastName?.charAt(0) || ''}
    </Avatar>
    <Typography
      variant="h4"
      sx={patientHeaderStyles.name}
    >
      {firstName || ''} {lastName || ''}
    </Typography>
    <Chip
      label='Active Patient'
      color='success'
      size='small'
      sx={patientHeaderStyles.statusChip}
    />
    {canEdit && (
      <StandardButton
        onClick={onEdit}
        variant="outlined"
        size="small"
        sx={{ mt: 2 }}
      >
        Edit Patient
      </StandardButton>
    )}
  </Box>
);