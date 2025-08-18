import { Breadcrumbs, Link, Typography } from '@mui/material';
import { Link as RouterLink } from 'react-router-dom';

interface BreadcrumbItem {
  label: string;
  path?: string;
}

interface BreadcrumbNavigationProps {
  items: BreadcrumbItem[];
}

export const BreadcrumbNavigation = ({ items }: BreadcrumbNavigationProps) => {
  return (
    <Breadcrumbs aria-label="breadcrumb" sx={{ mb: 2 }}>
      {items.map((item, index) => {
        const isLast = index === items.length - 1;
        
        if (isLast) {
          return (
            <Typography 
              key={index} 
              color="text.primary" 
              aria-current="page"
            >
              {item.label}
            </Typography>
          );
        }
        
        if (item.path) {
          return (
            <Link
              key={index}
              component={RouterLink}
              to={item.path}
              color="inherit"
              underline="hover"
            >
              {item.label}
            </Link>
          );
        }
        
        return (
          <Typography key={index} color="text.primary">
            {item.label}
          </Typography>
        );
      })}
    </Breadcrumbs>
  );
};