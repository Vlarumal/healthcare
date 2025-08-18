import {
  Box,
  Button,
  CircularProgress,
  Typography,
} from '@mui/material';
import { useState, useCallback, useId } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import LogoutButton from './LogoutButton';
import { guestUsers } from '../config/guestUsers';
import { getGuestPassword } from '../services/configService';

interface GuestLoginButtonsProps {
  loading?: boolean;
  disabled?: boolean;
}

export function GuestLoginButtons({
  loading,
  disabled = false,
}: GuestLoginButtonsProps) {
  const { login, isAuthenticated } = useAuth();
  const [error, setError] = useState('');
  const [loadingEmail, setLoadingEmail] = useState<string | null>(
    null
  );
  const warningId = useId();
  const errorId = useId();

  // Note: In production, ensure guest passwords are securely managed
  // and consider using temporary demo accounts instead of real credentials
  const navigate = useNavigate();

  const handleGuestLogin = useCallback(
    async (email: string) => {
      if (loading || loadingEmail) return;

      setLoadingEmail(email);
      setError('');

      try {
        const password = getGuestPassword();
        if (!password) {
          throw new Error('Guest login configuration error');
        }

        await login(email, password);
        navigate('/');
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Guest login failed'
        );
      } finally {
        setLoadingEmail(null);
      }
    },
    [login, navigate, setError, loading, loadingEmail]
  );

  if (isAuthenticated) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
        <LogoutButton />
      </Box>
    );
  }

  return (
    <section aria-labelledby={warningId}>
      <Typography
        id={warningId}
        variant='body2'
        sx={{ mt: 2, fontWeight: 'bold', color: 'error.main' }}
        align='center'
        role='alert'
        aria-live='assertive'
      >
        WARNING: Temporary Guest Login for Demo Only
      </Typography>
      {error && (
        <Typography
          id={errorId}
          color='error'
          align='center'
          sx={{ mt: 1 }}
          role='alert'
          aria-live='assertive'
        >
          {error}
        </Typography>
      )}
      <Box
        data-testid='guest-login-buttons'
        sx={{
          display: 'grid',
          gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' },
        }}
        gap={2}
        mt={1}
        aria-describedby={error ? errorId : undefined}
      >
        {guestUsers.map((user) => (
          <Button
            key={user.role}
            variant='outlined'
            onClick={() => handleGuestLogin(user.email)}
            aria-label={`Login as ${user.role}`}
            aria-busy={loadingEmail === user.email}
            disabled={disabled || loading || loadingEmail !== null}
            startIcon={
              loadingEmail === user.email && (
                <CircularProgress
                  size={20}
                  color='inherit'
                  aria-hidden='true'
                />
              )
            }
          >
            {loadingEmail === user.email
              ? 'Logging in...'
              : user.label}
          </Button>
        ))}
      </Box>
    </section>
  );
}

// Migrated from MUI LoadingButton to standard Button with loading state
// - Added CircularProgress for visual loading indication
// - Implemented proper accessibility attributes (aria-busy, aria-label)
// - Maintained consistent styling during loading state
