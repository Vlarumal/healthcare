const fs = require('fs');
const path = require('path');
const util = require('util');

const writeFile = util.promisify(fs.writeFile);
const access = util.promisify(fs.access);
const mkdir = util.promisify(fs.mkdir);

/**
 * Validates if a string is in PascalCase format
 * @param {string} str - The string to validate
 * @returns {boolean} True if valid PascalCase, false otherwise
 */
function isPascalCase(str) {
  return /^[A-Z][a-zA-Z0-9]*$/.test(str);
}

/**
 * Checks if a file exists
 * @param {string} filePath - Path to the file
 * @returns {Promise<boolean>} True if file exists, false otherwise
 */
async function fileExists(filePath) {
  try {
    await access(filePath, fs.constants.F_OK);
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Ensures a directory exists, creates it if needed
 * @param {string} dirPath - Path to the directory
 */
async function ensureDirectoryExists(dirPath) {
  try {
    await access(dirPath, fs.constants.F_OK);
  } catch (err) {
    await mkdir(dirPath, { recursive: true });
    console.log(`Created directory: ${dirPath}`);
  }
}

/**
 * Generates React component template
 * @param {string} name - Component name in PascalCase
 * @returns {string} Component template string
 */
const componentTemplate = (name) => `import React from 'react';
import styles from './${name}.module.css';

interface ${name}Props {
  // Add props here
}

/**
 * ${name} component
 * 
 * @component
 * @example
 * <${name} />
 */
const ${name}: React.FC<${name}Props> = (props) => {
  return (
    <div className={styles.container} data-testid="${name.toLowerCase()}-container">
      {/* ${name} component content */}
    </div>
  );
};

export default ${name};
`;

/**
 * Generates CSS module template
 * @param {string} name - Component name in PascalCase
 * @returns {string} CSS template string
 */
const cssTemplate = (name) => `.container {
  /* ${name} styles */
}`;

/**
 * Generates test file template
 * @param {string} name - Component name in PascalCase
 * @returns {string} Test template string
 */
const testTemplate = (name) => `import React from 'react';
import { render, screen } from '@testing-library/react';
import ${name} from './${name}';

describe('${name} Component', () => {
  test('renders without crashing', () => {
    render(<${name} />);
    expect(screen.getByTestId('${name.toLowerCase()}-container')).toBeInTheDocument();
  });

  test('renders with props', () => {
    // Example: render(<${name} prop="value" />);
    // Add assertions for prop-based rendering
  });
  
  test('matches snapshot', () => {
    const { asFragment } = render(<${name} />);
    expect(asFragment()).toMatchSnapshot();
  });
});
`;

/**
 * Main function to generate component files
 * @param {string} componentName - Component name in PascalCase
 */
async function generateComponent(componentName) {
  if (!componentName) {
    throw new Error('Component name is required');
  }

  if (!isPascalCase(componentName)) {
    throw new Error('Component name must be in PascalCase');
  }

  const componentsDir = path.join(__dirname, '../src/components');
  const componentPath = path.join(componentsDir, `${componentName}.tsx`);
  const cssPath = path.join(componentsDir, `${componentName}.module.css`);
  const testPath = path.join(componentsDir, `${componentName}.test.tsx`);

  await ensureDirectoryExists(componentsDir);

  if (await fileExists(componentPath)) {
    throw new Error(`Component file already exists: ${componentPath}`);
  }

  if (await fileExists(cssPath)) {
    throw new Error(`CSS file already exists: ${cssPath}`);
  }

  if (await fileExists(testPath)) {
    throw new Error(`Test file already exists: ${testPath}`);
  }

  try {
    await writeFile(componentPath, componentTemplate(componentName));
    console.log(`Created component: ${componentPath}`);
    
    await writeFile(cssPath, cssTemplate(componentName));
    console.log(`Created CSS module: ${cssPath}`);
    
    await writeFile(testPath, testTemplate(componentName));
    console.log(`Created test: ${testPath}`);
  } catch (err) {
    throw new Error(`Error generating files: ${err.message}`);
  }
}

(async () => {
  const componentName = process.argv[2];
  
  try {
    await generateComponent(componentName);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
})();