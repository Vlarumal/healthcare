# Healthcare Management System - Frontend

## Overview
React-based frontend for healthcare management system with TypeScript, Vite, and MUI components. Implements responsive UI with role-based access control.

## Dashboard Feature
The dashboard provides administrators with key metrics:
- Patient statistics (demographics, registration trends)
- Appointment tracking (upcoming, completion rates)
- System health monitoring (API performance, uptime)

### Implementation Details:
- Responsive grid layout with MUI Grid component
- Role-based access control (admin-only)
- WCAG 2.1 AA compliant

## Getting Started
1. Install dependencies: `npm install`
2. Configure environment variables (copy .env.example to .env)
3. Start development server: `npm run dev`

## Directory Structure
- `src/` - Source code
  - `pages/` - Top-level page components
  - `components/` - Reusable UI components
  - `services/` - API service layer
  - `contexts/` - Global state management
  - `hooks/` - Custom React hooks
- `public/` - Static assets
- `tests/` - Component tests

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      ...tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      ...tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      ...tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
