import {
  createTheme,
  responsiveFontSizes,
} from '@mui/material/styles';
import '@mui/material/Button';

declare module '@mui/material/Button' {
  interface ButtonPropsVariantOverrides {
    dashed: true;
  }
}

const baseTheme = createTheme({
  zIndex: {
    appBar: 1200,
    drawer: 1100,
    modal: 1300,
    tooltip: 1500,
    snackbar: 1400,
  },
  palette: {
    primary: { main: '#1565c0' },
    secondary: { main: '#8e24aa' },
    error: { main: '#f44336' },
    warning: { main: '#ed6c02' },
    info: { main: '#2196f3' },
    success: { main: '#2e7d32' },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
    text: {
      primary: '#212121',
      secondary: '#616161',
    },
  },
  spacing: (factor: number) => `${0.5 * factor}rem`,
  typography: {
    fontFamily: 'Roboto, sans-serif',
    h1: { fontSize: '2.5rem', fontWeight: 500 },
    h2: { fontSize: '2rem', fontWeight: 500 },
    h3: { fontSize: '1.75rem', fontWeight: 500 },
    h4: { fontSize: '1.5rem', fontWeight: 500 },
    h5: { fontSize: '1.25rem', fontWeight: 500 },
    h6: { fontSize: '1rem', fontWeight: 500 },
    body1: { fontSize: '1rem' },
    body2: { fontSize: '0.875rem' },
    button: {
      textTransform: 'none',
      fontWeight: 500,
    },
  },
  breakpoints: {
    values: {
      xs: 0,
      sm: 600,
      md: 960,
      lg: 1280,
      xl: 1920,
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      defaultProps: {
        variant: 'contained',
      },
      styleOverrides: {
        root: {
          textTransform: 'none',
          padding: '6px 16px',
          fontSize: '0.875rem',
          boxShadow: 'none',
          marginTop: '1.5rem',
          '&:hover': {
            boxShadow: '0px 2px 4px -1px rgba(0,0,0,0.2)',
          },
          '&:focus-visible': {
            outline: '2px solid currentColor',
            outlineOffset: '2px',
          },
          '&.Mui-disabled': { opacity: 0.6 },
        },
      },
      variants: [
        {
          props: { variant: 'dashed' },
          style: {
            border: `2px dashed currentColor`,
            backgroundColor: 'transparent',
          },
        },
      ],
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          '&:focus-visible': {
            outline: '2px solid currentColor',
            outlineOffset: '2px',
          },
        },
      },
    },
    MuiAppBar: {
      defaultProps: {
        color: 'primary',
      },
      styleOverrides: {
        root: {
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          zIndex: 1200,
          padding: '0 24px',
          '@media (max-width: 600px)': {
            padding: '0 16px',
          },
        },
      },
    },
    MuiSvgIcon: {
      variants: [
        {
          props: { fontSize: 'large' },
          style: { fontSize: '2rem' },
        },
      ],
      styleOverrides: {
        root: {
          fontSize: '1.25rem',
        },
      },
    },
    MuiContainer: {
      styleOverrides: {
        root: {
          paddingTop: 3,
          paddingBottom: 3,
        },
      },
    },
    MuiTextField: {
      defaultProps: {
        variant: 'outlined',
      },
      styleOverrides: {
        root: {
          marginBottom: '1rem',
        },
      },
    },
    MuiFormControl: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-notchedOutline': {
            borderColor: '#4a90e2',
          },
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        root: {
          '&:hover .MuiOutlinedInput-notchedOutline': {
            borderColor: '#1565c0',
          },
          '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
            borderColor: '#1565c0',
            borderWidth: '1px',
          },
        },
      },
    },
    MuiStack: {
      styleOverrides: {
        root: {
          marginTop: '1rem',
        },
      },
    },
  },
});

export const darkTheme = responsiveFontSizes(
  createTheme({
    ...baseTheme,
    palette: {
      mode: 'dark',
      primary: { main: '#1976d2' },
      secondary: { main: '#d81b60' },
      error: { main: '#ef5350' },
      warning: { main: '#ffb74d' },
      success: { main: '#81c784' },
      background: {
        default: '#121212',
        paper: '#1e1e1e',
      },
      text: {
        primary: '#f5f5f5',
        secondary: 'rgba(255, 255, 255, 0.7)',
      },
    },
  })
);

const theme = responsiveFontSizes(baseTheme);

export default theme;
