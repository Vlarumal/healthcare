import { useTheme } from '@mui/material/styles';
import Link from '@mui/material/Link';

export default function SkipNavigationLink() {
  const theme = useTheme();
  
  return (
    <Link
      href="#main-content"
      tabIndex={0}
      sx={{
        position: 'absolute',
        left: theme.spacing(2),
        backgroundColor: theme.palette.background.paper,
        color: theme.palette.text.primary,
        padding: theme.spacing(1),
        zIndex: theme.zIndex.modal + 1,
        transform: 'translateY(-100%)',
        transition: 'transform 0.3s',
        '&:focus': {
          transform: 'translateY(0)'
        }
      }}
    >
      Skip to content
    </Link>
  );
}