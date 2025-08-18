import { useState, useCallback } from 'react';
import {
  TextField,
  MenuItem,
  Stack,
} from '@mui/material';
import { useTheme } from '@mui/material/styles';
import useMediaQuery from '@mui/material/useMediaQuery';
import { StandardButton } from './common/StandardButton';

interface PatientFilters {
  firstName: string;
  lastName: string;
  email: string;
  startDate: string;
  endDate: string;
  gender: string;
}

interface PatientFilterProps {
  onApplyFilters: (filters: Record<string, string>) => void;
  onResetFilters: () => void;
}

export const PatientFilter = ({ onApplyFilters, onResetFilters }: PatientFilterProps) => {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const [filters, setFilters] = useState<PatientFilters>({
    firstName: '',
    lastName: '',
    email: '',
    startDate: '',
    endDate: '',
    gender: ''
  });

  const currentDate = new Date().toISOString().split('T')[0];

  const handleApplyFilters = useCallback(() => {
    // Format dates to ISO string and remove empty filters
    const formattedFilters = Object.entries(filters).reduce((acc, [key, value]) => {
      if (value) {
        if (key === 'startDate' || key === 'endDate') {
          // Format date to YYYY-MM-DD
          acc[key] = value; // Use the value directly since it's already in YYYY-MM-DD format from the date input
        } else {
          acc[key] = value;
        }
      }
      return acc;
    }, {} as Record<string, string>);
    
    onApplyFilters(formattedFilters);
  }, [filters, onApplyFilters]);

  const handleResetFilters = useCallback(() => {
    setFilters({
      firstName: '',
      lastName: '',
      email: '',
      startDate: '',
      endDate: '',
      gender: ''
    });
    onResetFilters();
  }, [onResetFilters]);

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fill, minmax(300px, 1fr))',
      gap: '16px'
    }}>
      <TextField
        label="First Name"
        value={filters.firstName}
        onChange={useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
          setFilters(prev => ({...prev, firstName: e.target.value}));
        }, [])}
        fullWidth
        size="small"
      />
      <TextField
        label="Last Name"
        value={filters.lastName}
        onChange={useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
          setFilters(prev => ({...prev, lastName: e.target.value}));
        }, [])}
        fullWidth
        size="small"
      />
      <TextField
        label="Email"
        value={filters.email}
        onChange={useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
          setFilters(prev => ({...prev, email: e.target.value}));
        }, [])}
        fullWidth
        size="small"
      />
      <TextField
        select
        label="Gender"
        value={filters.gender}
        onChange={useCallback((e: React.ChangeEvent<{ value: unknown }>) => {
          setFilters(prev => ({...prev, gender: e.target.value as string}));
        }, [])}
        fullWidth
        size="small"
      >
        <MenuItem value="">All</MenuItem>
        <MenuItem value="male">Male</MenuItem>
        <MenuItem value="female">Female</MenuItem>
        <MenuItem value="other">Other</MenuItem>
        <MenuItem value="unspecified">Unspecified</MenuItem>
      </TextField>
      <TextField
        label="Date of Birth (Start)"
        type="date"
        value={filters.startDate}
        onChange={useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
          setFilters(prev => ({...prev, startDate: e.target.value}));
        }, [])}
        fullWidth
        size="small"
        slotProps={{
          inputLabel: { shrink: true },
          htmlInput: {
            max: filters.endDate || currentDate
          }
        }}
      />
      <TextField
        label="Date of Birth (End)"
        type="date"
        value={filters.endDate}
        onChange={useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
          setFilters(prev => ({...prev, endDate: e.target.value}));
        }, [])}
        fullWidth
        size="small"
        slotProps={{
          inputLabel: { shrink: true },
          htmlInput: {
            min: filters.startDate,
            max: currentDate
          }
        }}
      />
      <Stack direction="row" spacing={2} sx={{ mt: 2, gridColumn: '1 / -1' }}>
        <StandardButton
          variant="contained"
          label="Apply Filters"
          onClick={handleApplyFilters}
        />
        <StandardButton
          variant="outlined"
          label="Reset Filters"
          onClick={handleResetFilters}
        />
      </Stack>
    </div>
  );
};