import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import ThemeToggle from '../ThemeToggle';
import LogoutButton from '../LogoutButton';
import { useAuth } from '../../hooks/useAuth';
import { Link } from 'react-router-dom';
import Button from '@mui/material/Button';
import DashboardOutlined from '@mui/icons-material/DashboardOutlined';

interface DesktopActionsProps {
  isAuthenticated: boolean;
}

const DesktopActions = ({ isAuthenticated }: DesktopActionsProps) => {
  const theme = useTheme();
  const { user } = useAuth();

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: theme.spacing(2),
        paddingRight: theme.spacing(2),
      }}
      aria-labelledby='app-header-title'
    >
      {isAuthenticated && user?.role === 'admin' && (
        <Button
          component={Link}
          to="/dashboard"
          variant="outlined"
          color="inherit"
          startIcon={<DashboardOutlined />}
          aria-label="Dashboard"
        >
          Dashboard
        </Button>
      )}
      <ThemeToggle />
      {isAuthenticated && <LogoutButton />}
    </Box>
  );
};

export default DesktopActions;
