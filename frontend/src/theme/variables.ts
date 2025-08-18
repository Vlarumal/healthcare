export const detailSectionStyles = {
  spacing: {
    section: 4,
    item: 2,
  },
  header: {
    gutterBottom: true,
    fontWeight: 600,
    color: 'text.primary',
    mb: 2,
  },
};

export const detailItemStyles = {
  container: {
  },
  label: {
    color: 'text.secondary',
    role: "term"
  },
  value: {
    fontWeight: 'medium',
    color: 'text.primary',
    role: "definition"
  },
  error: {
    color: 'error.main',
  },
};

export const layoutStyles = {
  centeredContainer: {
    maxWidth: 600,
    mx: 'auto',
  },
  headerStyle: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
  },
};

export const patientHeaderStyles = {
  avatar: {
    width: 120,
    height: 120,
    fontSize: 48,
    bgcolor: 'primary.main',
    mb: 2,
  },
  name: {
    fontWeight: 'bold',
    color: 'text.primary',
  },
  statusChip: {
    mt: 1,
  }
};

export const medicalHistorySectionStyles = {
  alert: {
    mt: 2,
  }
};

export const loadingStateStyles = {
  skeletonContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: { xs: 1, sm: 1 },
  },
  skeleton: {
    height: 60,
  }
};