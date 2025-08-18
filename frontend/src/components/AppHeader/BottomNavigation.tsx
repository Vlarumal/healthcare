import { BottomNavigation, BottomNavigationAction, Paper } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { Home, People, Dashboard, Person } from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';

export default function BottomNavigationMenu() {
  const location = useLocation();
  const { user, isAuthenticated } = useAuth();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));

  if (!isMobile) {
    return null;
  }

  const getCurrentValue = () => {
    if (location.pathname === '/') return '/';
    if (location.pathname === '/dashboard') return '/dashboard';
    if (location.pathname.startsWith('/patients/')) return '/patients';
    return location.pathname;
  };

  return (
    <Paper
      sx={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 1000,
      }}
      elevation={3}
    >
      <BottomNavigation
        showLabels
        value={getCurrentValue()}
      >
        <BottomNavigationAction
          label="Home"
          value="/"
          icon={<Home />}
          component={Link}
          to="/"
        />
        
        {isAuthenticated && user?.role !== 'patient' && (
          <BottomNavigationAction
            label="Patients"
            value="/patients"
            icon={<People />}
            component={Link}
            to="/"
          />
        )}
        
        {isAuthenticated && user?.role === 'admin' && (
          <BottomNavigationAction
            label="Dashboard"
            value="/dashboard"
            icon={<Dashboard />}
            component={Link}
            to="/dashboard"
          />
        )}
        
        {isAuthenticated && user?.role === 'patient' && (
          <BottomNavigationAction
            label="Profile"
            value="/patients/me"
            icon={<Person />}
            component={Link}
            to="/patients/me"
          />
        )}
      </BottomNavigation>
    </Paper>
  );
}