import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import termsContent from '../content/termsOfService.json';
import { useTheme } from '@mui/material/styles';

interface Section {
  title: string;
  content: string;
}

export function TermsOfServicePage() {
  const theme = useTheme();
  
  return (
    <Box
      component="main"
      sx={{
        maxWidth: 800,
        mx: 'auto',
        p: 4,
        [theme.breakpoints.down('sm')]: {
          p: 2
        }
      }}
      aria-labelledby="terms-title"
    >
      <Typography
        id="terms-title"
        variant="h4"
        component="h1"
        gutterBottom
        sx={{
          fontSize: {
            xs: '1.75rem',
            sm: '2rem',
            md: '2.125rem'
          }
        }}
      >
        {termsContent.title}
      </Typography>
      
      {termsContent.sections.map((section: Section, index: number) => (
        <Box key={index} sx={{ mb: 4 }} aria-labelledby={`section-${index}-title`}>
          <Typography
            id={`section-${index}-title`}
            variant="h5"
            component="h2"
            gutterBottom
            sx={{
              fontSize: {
                xs: '1.25rem',
                sm: '1.5rem',
                md: '1.6rem'
              }
            }}
          >
            {section.title}
          </Typography>
          <Typography
            component="div"
            sx={{
              fontSize: {
                xs: '0.9rem',
                sm: '1rem'
              }
            }}
          >
            {section.content}
          </Typography>
        </Box>
      ))}
    </Box>
  );
}