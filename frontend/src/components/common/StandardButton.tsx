import { Button, type ButtonProps } from '@mui/material';
import { forwardRef } from 'react';

export interface StandardButtonProps extends ButtonProps {
  label?: string;
}

export const StandardButton = forwardRef<HTMLButtonElement, StandardButtonProps>(({
  label,
  children,
  ...props
}, ref) => {
  return (
    <Button
      ref={ref}
      {...props}
    >
      {label || children}
    </Button>
  );
});