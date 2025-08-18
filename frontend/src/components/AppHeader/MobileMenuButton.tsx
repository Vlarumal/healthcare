import { memo, forwardRef, useCallback } from 'react';
import IconButton from '@mui/material/IconButton';
import MenuIcon from '@mui/icons-material/Menu';
import { useTheme } from '@mui/material/styles';

interface MobileMenuButtonProps {
  menuOpen: boolean;
  handleMenuOpen: (event: React.MouseEvent<HTMLButtonElement>) => void;
}

const MobileMenuButton = memo(
  forwardRef<HTMLButtonElement, MobileMenuButtonProps>(
    ({ menuOpen, handleMenuOpen }, ref) => {
      const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          handleMenuOpen(e as unknown as React.MouseEvent<HTMLButtonElement>);
        }
      }, [handleMenuOpen]);

      const theme = useTheme();
      
      return (
        <IconButton
          edge="start"
          color="inherit"
          aria-label={menuOpen ? "Close menu" : "Open menu"}
          id="menu-button"
          aria-controls={menuOpen ? 'mobile-menu' : undefined}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          sx={{ mr: theme.spacing(2) }}
          onClick={handleMenuOpen}
          onKeyDown={handleKeyDown}
          size="large"
          ref={ref}
          tabIndex={0}
        >
          <MenuIcon aria-hidden="true" />
        </IconButton>
      );
    }
  ),
  (prev, next) => prev.menuOpen === next.menuOpen
);

export default MobileMenuButton;