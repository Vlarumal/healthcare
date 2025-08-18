import type { JSX } from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import type { User } from '../../types/auth';

interface ProtectedRouteProps {
  children: JSX.Element;
  allowedRoles?: User['role'][];
}

export const ProtectedRoute = ({ 
  children, 
  allowedRoles 
}: ProtectedRouteProps): JSX.Element => {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return (
      <Box 
        display="flex" 
        flexDirection="column" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="100vh"
        gap={2}
      >
        <CircularProgress size={60} />
        <Typography variant="h6">Verifying authentication...</Typography>
      </Box>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && user && !allowedRoles.includes(user.role)) {
    return (
      <Box 
        display="flex" 
        justifyContent="center" 
        alignItems="center" 
        minHeight="100vh"
        p={2}
      >
        <Alert 
          severity="error" 
          variant="outlined"
          sx={{ 
            width: '100%', 
            maxWidth: 400,
            textAlign: 'center'
          }}
        >
          <Typography variant="h6" gutterBottom>
            Access Denied
          </Typography>
          <Typography variant="body2">
            You don't have permission to access this page.
          </Typography>
          <Box mt={2}>
            <Typography variant="body2" color="textSecondary">
              Your role: {user.role}
            </Typography>
          </Box>
        </Alert>
      </Box>
    );
  }

  return children;
};