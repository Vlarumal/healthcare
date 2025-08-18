import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { StandardButton, type StandardButtonProps } from './StandardButton';

interface BackButtonProps extends Omit<StandardButtonProps, 'onClick'> {
  to?: string;
  label?: string;
}

export const BackButton = ({
  to = '/',
  label = 'Back',
  ...buttonProps
}: BackButtonProps) => {
  const navigate = useNavigate();
  
  const handleBack = useCallback(() => {
    navigate(to);
  }, [navigate, to]);

  return (
    <StandardButton
      onClick={handleBack}
      {...buttonProps}
    >
      {label}
    </StandardButton>
  );
};