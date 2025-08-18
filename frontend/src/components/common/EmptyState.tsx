import { Box, Typography } from '@mui/material';
import { StandardButton, type StandardButtonProps } from './StandardButton';
import { forwardRef } from 'react';

export interface EmptyStateProps {
  title: string;
  description: string;
  actionText?: string;
  onClickAction?: () => void;
  buttonProps?: StandardButtonProps;
}

export const EmptyState = forwardRef<HTMLDivElement, EmptyStateProps>(({
  title,
  description,
  actionText,
  onClickAction,
  buttonProps
}, ref) => {
  return (
    <Box
      ref={ref}
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      mt={4}
      p={4}
      textAlign="center"
    >
      <Typography variant="h6" color="textSecondary" gutterBottom>
        {title}
      </Typography>
      <Typography variant="body1" color="textSecondary" component="p">
        {description}
      </Typography>
      {actionText && onClickAction && (
        <StandardButton
          variant="contained"
          color="primary"
          onClick={onClickAction}
          sx={{ mt: 2 }}
          label={actionText}
          {...buttonProps}
        />
      )}
    </Box>
  );
});