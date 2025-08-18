import { Box, Typography } from '@mui/material';

interface DetailItemProps {
  label: string;
  value: string;
  error?: string;
  errorId?: string;
}

export const DetailItem = ({ label, value, error, errorId }: DetailItemProps) => (
  <Box data-testid="detail-item">
    <Typography
      variant='subtitle2'
      sx={{ color: 'text.secondary' }}
      role="term"
    >
      {label}:
    </Typography>
    <Typography
      variant='body1'
      fontWeight='medium'
      sx={{ color: 'text.primary' }}
      role="definition"
      {...(error && errorId ? { 'aria-errormessage': errorId } : {})}
    >
      {value}
    </Typography>
    {error && (
      <Typography
        variant='caption'
        color='error'
        id={errorId}
      >
        {error}
      </Typography>
    )}
  </Box>
);