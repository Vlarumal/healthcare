import { Box, Typography } from '@mui/material';
import type { ReactNode } from 'react';

interface DetailSectionProps {
  title: string;
  children: ReactNode;
  headerActions?: ReactNode;
}

export const DetailSection = ({ title, children, headerActions }: DetailSectionProps) => (
  <Box sx={{ mt: 4 }}>
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
      <Typography
        variant='h5'
        gutterBottom
        sx={{ fontWeight: 600, color: 'text.primary', mb: 0 }}
      >
        {title}
      </Typography>
      {headerActions}
    </Box>
    {children}
  </Box>
);