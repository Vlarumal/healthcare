import { Box, Typography, Button } from '@mui/material';

interface EmptyStateProps {
  title: string;
  description: string;
  actionText?: string;
  onClickAction?: () => void;
}

export const EmptyState = ({
  title,
  description,
  actionText,
  onClickAction
}: EmptyStateProps) => {
  return (
    <Box
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
        <Button
          variant="contained"
          color="primary"
          onClick={onClickAction}
          sx={{ mt: 2 }}
        >
          {actionText}
        </Button>
      )}
    </Box>
  );
};