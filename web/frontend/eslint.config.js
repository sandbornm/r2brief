import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import reactX from 'eslint-plugin-react-x';
import tseslint from 'typescript-eslint';

// ESLint 10 reads this file only. typescript-eslint 8.72 still peers
// TypeScript <6.1, so the recommended set stays non-type-checked.
// eslint-plugin-react 7.37.5 peers ESLint ^9.7 and has no ESLint 10 release.
// react-hooks 7.1.1 peers ESLint 10. react-x supplies the jsx-key check
// as react-x/no-missing-key.
export default tseslint.config(
  { ignores: ['dist/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
      'react-x': reactX,
    },
    languageOptions: {
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
    rules: {
      // flat.recommended in react-hooks 7 also turns on the React Compiler
      // rules. Those are new failures across the app, not the jsx-key and
      // rules-of-hooks coverage this config is restoring.
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react-x/no-missing-key': 'error',
    },
  },
);
