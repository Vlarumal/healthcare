import { Box, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';
import { People, History, Event, Settings } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';

interface QuickAccessItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

interface QuickAccessSidebarProps {
  items?: QuickAccessItem[];
}

const defaultItems: QuickAccessItem[] = [
  { label: 'Patient List', path: '/', icon: <People /> },
  { label: 'Medical History', path: '/patients', icon: <History /> },
  { label: 'Appointments', path: '/', icon: <Event /> },
  { label: 'System Settings', path: '/dashboard', icon: <Settings /> },
];

export const QuickAccessSidebar = ({ items = defaultItems }: QuickAccessSidebarProps) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  
  // On mobile, we'll use the bottom navigation instead
  if (isMobile) {
    return null;
  }

  return (
    <Box
      component="nav"
      aria-label="Quick access navigation"
      sx={{
        width: 240,
        flexShrink: 0,
        borderRight: 1,
        borderColor: 'divider',
        height: 'calc(100vh - 64px)',
        position: 'fixed',
        top: 64,
        left: 0,
        overflowY: 'auto',
        bgcolor: 'background.paper',
        pt: 2,
      }}
    >
      <Typography
        variant="h6"
        sx={{ mt: 2, px: 2, pb: 1, fontWeight: 600 }}
        id="quick-access-heading"
      >
        Quick Access
      </Typography>
      <Divider />
      <List>
        {items.map((item, index) => (
          <ListItem key={index} disablePadding>
            <ListItemButton
              component={RouterLink}
              to={item.path}
              sx={{
                minHeight: 48,
                px: 2.5,
              }}
            >
              <ListItemIcon sx={{ minWidth: 0, mr: 3, justifyContent: 'center' }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={item.label}
                slotProps={{
                  primary: {
                    sx: { fontWeight: 500 }
                  }
                }}
              />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </Box>
  );
};