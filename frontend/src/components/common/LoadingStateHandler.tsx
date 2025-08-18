import { Box, Skeleton } from '@mui/material';
import { loadingStateStyles } from '../../theme/variables';

interface LoadingStateHandlerProps {
  count?: number;
}

export const LoadingStateHandler = ({ count = 3 }: LoadingStateHandlerProps) => (
  <Box sx={loadingStateStyles.skeletonContainer}>
    <div role="progressbar" aria-hidden="true" style={{ position: 'absolute', width: 0, height: 0, overflow: 'hidden' }} />
    {Array.from({ length: count }).map((_, index) => (
      <Skeleton key={index} sx={loadingStateStyles.skeleton} />
    ))}
  </Box>
);