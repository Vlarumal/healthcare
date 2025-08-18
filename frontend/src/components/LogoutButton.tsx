import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import { useAuth } from '../hooks/useAuth';
import { useState } from 'react';
import { StandardButton } from './common/StandardButton';

const LogoutButton: React.FC = () => {
  const { logout } = useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogout = async () => {
    setIsLoading(true);
    setError(null);
    try {
      await logout();
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('Logout failed:', error);
      }
      setError('Logout failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      handleLogout();
    }
  };

  return (
    <Box>
      <StandardButton
        sx={{ mb: 3 }}
        variant='outlined'
        color='error'
        onClick={handleLogout}
        onKeyDown={handleKeyDown}
        disabled={isLoading}
        aria-label={isLoading ? 'Logging out' : 'Logout'}
        aria-describedby={error ? 'logout-error' : undefined}
        aria-busy={isLoading}
        startIcon={
          isLoading && (
            <CircularProgress
              size={20}
              color='inherit'
              aria-hidden='true'
            />
          )
        }
      >
        {isLoading ? 'Logging out...' : 'Logout'}
      </StandardButton>
      {error && (
        <Typography
          id='logout-error'
          color='error'
          role='alert'
          aria-live='assertive'
          mt={1}
          sx={{ fontSize: '0.875rem' }}
        >
          {error}
        </Typography>
      )}
    </Box>
  );
};

export default LogoutButton;
