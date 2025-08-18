import { IconButton, Tooltip } from '@mui/material';
import { useTheme } from '../hooks/useTheme';
import { DarkMode, LightMode } from '@mui/icons-material';

const ThemeToggle = () => {
  const { darkMode, toggleTheme } = useTheme();

  return (
    <Tooltip title={darkMode ? "Switch to light mode" : "Switch to dark mode"}>
      <IconButton 
        color="inherit" 
        onClick={toggleTheme}
        aria-label="toggle theme"
        sx={{ ml: 1 }}
      >
        {darkMode ? <LightMode sx={{ color: (theme) => theme.palette.warning.main }} /> : <DarkMode />}
      </IconButton>
    </Tooltip>
  );
};

export default ThemeToggle;