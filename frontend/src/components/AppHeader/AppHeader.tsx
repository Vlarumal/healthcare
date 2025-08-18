import { useState, useRef, useEffect, useCallback } from 'react';
import { useAuth } from '../../hooks/useAuth';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import ScreenReaderAnnouncement from './ScreenReaderAnnouncement';
import Typography from '@mui/material/Typography';
import useMediaQuery from '@mui/material/useMediaQuery';

import { useTheme } from '@mui/material/styles';
import DesktopActions from './DesktopActions';
import MobileMenuButton from './MobileMenuButton';
import MobileMenu from './MobileMenu';

export default function AppHeader() {
  const { isAuthenticated } = useAuth();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'), {
    noSsr: true,
  });
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const menuOpen = Boolean(anchorEl);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const announcementRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (announcementRef.current) {
      announcementRef.current.textContent = menuOpen
        ? 'Mobile menu opened'
        : 'Mobile menu closed';
    }
  }, [menuOpen]);

  const handleMenuOpen = useCallback(
    (event: React.MouseEvent<HTMLButtonElement>) => {
      setAnchorEl(event.currentTarget);
    },
    []
  );

  const handleMenuClose = useCallback(() => {
    setAnchorEl(null);
    setTimeout(() => {
      menuButtonRef.current?.focus();
    }, 0);
  }, []);

  return (
    <>
      <ScreenReaderAnnouncement ref={announcementRef} />
      <AppBar
        position='fixed'
        enableColorOnDark
        role='banner'
        aria-label='Main navigation'
        sx={{
          top: 0,
          zIndex: theme.zIndex.drawer + 1,
          mb: 1,
          [theme.breakpoints.down('sm')]: {
            mb: 0.5,
          },
        }}
      >
        <Toolbar>
          {isMobile && (
            <MobileMenuButton
              menuOpen={menuOpen}
              handleMenuOpen={handleMenuOpen}
              ref={menuButtonRef}
            />
          )}
          <Typography
            variant={isMobile ? 'subtitle1' : 'h6'}
            component='div'
            sx={{
              flexGrow: 1,
              fontWeight: isMobile ? 500 : 600,
              fontSize: isMobile ? '1.1rem' : '1.25rem',
            }}
            id='app-header-title'
          >
            Healthcare Management System
          </Typography>

          {!isMobile && (
            <DesktopActions isAuthenticated={isAuthenticated} />
          )}
        </Toolbar>

        {isMobile && menuOpen && (
          <MobileMenu
            anchorEl={anchorEl}
            menuOpen={menuOpen}
            handleMenuClose={handleMenuClose}
            isAuthenticated={isAuthenticated}
          />
        )}
      </AppBar>
      <Toolbar />
    </>
  );
}
