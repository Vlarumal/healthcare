import { Alert, AlertTitle, type AlertProps } from '@mui/material';
import { forwardRef } from 'react';

export interface ErrorDisplayProps extends AlertProps {
  title?: string;
  message: string;
}

export const ErrorDisplay = forwardRef<HTMLDivElement, ErrorDisplayProps>(({
  title,
  message,
  ...props
}, ref) => {
  return (
    <Alert
      ref={ref}
      severity="error"
      {...props}
    >
      {title && <AlertTitle>{title}</AlertTitle>}
      {message}
    </Alert>
  );
});