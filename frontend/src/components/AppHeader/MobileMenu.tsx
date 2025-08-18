import { useTheme } from '@mui/material/styles';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import ThemeToggle from '../ThemeToggle';
import LogoutButton from '../LogoutButton';
import { useAuth } from '../../hooks/useAuth';
import { Link, useLocation } from 'react-router-dom';
import DashboardOutlined from '@mui/icons-material/DashboardOutlined';

interface MobileMenuProps {
  menuOpen: boolean;
  anchorEl: HTMLElement | null;
  handleMenuClose: () => void;
  isAuthenticated: boolean;
}

export default function MobileMenu({
  menuOpen,
  anchorEl,
  handleMenuClose,
  isAuthenticated
}: MobileMenuProps) {
  const theme = useTheme();
  const { user } = useAuth();
  const location = useLocation();

  return (
    <Menu
      id="mobile-menu"
      aria-labelledby="menu-button"
      anchorEl={anchorEl}
      open={menuOpen}
      onClose={handleMenuClose}
      anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
      transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      slotProps={{
        paper: {
          sx: {
            width: '100%',
            maxWidth: 'none',
            [theme.breakpoints.down('sm')]: {
              marginTop: '4px'
            }
          }
        },
        list: {
          'aria-labelledby': 'menu-button',
          role: 'menu'
        }
      }}
    >
      {isAuthenticated && user?.role === 'admin' && (
        <MenuItem
          onClick={handleMenuClose}
          role="menuitem"
          aria-label="Dashboard"
          tabIndex={-1}
        >
          <Button
            component={Link}
            to="/dashboard"
            variant={location.pathname === '/dashboard' ? 'contained' : 'outlined'}
            color="primary"
            fullWidth
            startIcon={<DashboardOutlined />}
          >
            Dashboard
          </Button>
        </MenuItem>
      )}
      {isAuthenticated && user?.role !== 'patient' && (
        <MenuItem
          onClick={handleMenuClose}
          role="menuitem"
          aria-label="Patient List"
          tabIndex={-1}
        >
          <Button
            component={Link}
            to="/"
            variant={location.pathname === '/' ? 'contained' : 'outlined'}
            color="primary"
            fullWidth
          >
            Patient List
          </Button>
        </MenuItem>
      )}
      <MenuItem
        onClick={handleMenuClose}
        role="menuitem"
        aria-label="Toggle theme"
        tabIndex={-1}
      >
        <ThemeToggle />
      </MenuItem>
      {isAuthenticated && (
        <MenuItem
          role="menuitem"
          aria-label="Logout"
          tabIndex={-1}
        >
          <LogoutButton />
        </MenuItem>
      )}
    </Menu>
  );
}