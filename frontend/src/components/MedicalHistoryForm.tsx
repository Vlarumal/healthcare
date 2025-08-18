import { useState, useEffect } from 'react';
import type { MedicalHistory, MedicalHistoryCreate, MedicalHistoryUpdate } from '../types/medicalHistory';
import { MedicalHistoryService } from '../services';
import dayjs, { Dayjs } from 'dayjs';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Button,
  FormControl,
  Box
} from '@mui/material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { ErrorDisplay } from './common/ErrorDisplay';
import { sanitizeInput } from '../utils/sanitization';

interface MedicalHistoryFormProps {
  patientId: string;
  existingHistory?: MedicalHistory;
  onSuccess: () => void;
  onCancel: () => void;
}

export const MedicalHistoryForm = ({
  patientId,
  existingHistory,
  onSuccess,
  onCancel
}: MedicalHistoryFormProps) => {
  const [date, setDate] = useState<Dayjs | null>(dayjs().startOf('day'));
  const [diagnosis, setDiagnosis] = useState('');
  const [treatment, setTreatment] = useState('');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState<string>();
  const [submitting, setSubmitting] = useState(false);
  const [validationErrors, setValidationErrors] = useState({
    date: '',
    diagnosis: '',
    treatment: '',
    notes: ''
  });

  useEffect(() => {
    if (existingHistory) {
      setDate(dayjs(existingHistory.date));
      setDiagnosis(existingHistory.diagnosis);
      setTreatment(existingHistory.treatment);
      setNotes(existingHistory.notes || '');
    } else {
      setDate(dayjs().startOf('day'));
      setDiagnosis('');
      setTreatment('');
      setNotes('');
    }
  }, [existingHistory]);

  const validateForm = () => {
    const errors = {
      date: !date ? 'Please select a date' : '',
      diagnosis: !diagnosis ? 'Diagnosis is required' :
                diagnosis.length < 5 ? 'Minimum 5 characters' :
                diagnosis.length > 500 ? 'Maximum 500 characters' : '',
      treatment: !treatment ? 'Treatment is required' :
                 treatment.length < 5 ? 'Minimum 5 characters' :
                 treatment.length > 500 ? 'Maximum 500 characters' : '',
      notes: notes.length > 1000 ? 'Maximum 1000 characters' : ''
    };
    
    setValidationErrors(errors);
    return !Object.values(errors).some(error => error !== '');
  };

  const handleSubmit = async () => {
    if (!validateForm()) return;
    
    try {
      setSubmitting(true);
      setError(undefined);
      
      const apiValues = {
        patientId: Number(patientId),
        date: date?.format('YYYY-MM-DD') || '',
        diagnosis: sanitizeInput(diagnosis),
        treatment: sanitizeInput(treatment),
        notes: sanitizeInput(notes)
      };

      if (existingHistory) {
        await MedicalHistoryService.update(existingHistory.id, apiValues as MedicalHistoryUpdate);
      } else {
        await MedicalHistoryService.create(apiValues as MedicalHistoryCreate);
      }
      
      onSuccess();
      onCancel();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save medical history');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open onClose={onCancel} fullWidth maxWidth="sm">
      <DialogTitle>{existingHistory ? "Edit Medical Entry" : "New Medical Entry"}</DialogTitle>
      
      <DialogContent>
        {error && (
          <ErrorDisplay
            message={error}
            sx={{ mb: 2 }}
          />
        )}
        
        <Box component="form" sx={{ mt: 1 }}>
          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <FormControl fullWidth margin="normal" error={!!validationErrors.date}>
              <DatePicker
                label="Date"
                value={date}
                onChange={(newValue) => setDate(newValue)}
                maxDate={dayjs()}
                format="YYYY-MM-DD"
                slotProps={{
                  textField: {
                    helperText: validationErrors.date
                  }
                }}
              />
            </FormControl>
          </LocalizationProvider>
          
          <TextField
            label="Diagnosis"
            value={diagnosis}
            onChange={(e) => setDiagnosis(e.target.value)}
            fullWidth
            margin="normal"
            multiline
            rows={3}
            error={!!validationErrors.diagnosis}
            helperText={validationErrors.diagnosis}
            slotProps={{ htmlInput: { maxLength: 500 } }}
          />
          
          <TextField
            label="Treatment"
            value={treatment}
            onChange={(e) => setTreatment(e.target.value)}
            fullWidth
            margin="normal"
            multiline
            rows={3}
            error={!!validationErrors.treatment}
            helperText={validationErrors.treatment}
            slotProps={{ htmlInput: { maxLength: 500 } }}
          />
          
          <TextField
            label="Notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            fullWidth
            margin="normal"
            multiline
            rows={2}
            error={!!validationErrors.notes}
            helperText={validationErrors.notes}
            slotProps={{ htmlInput: { maxLength: 1000 } }}
          />
        </Box>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onCancel} disabled={submitting}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleSubmit}
          disabled={submitting}
        >
          {submitting ? 'Submitting...' : 'Submit'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};