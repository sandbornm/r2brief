import js from '@eslint/js';
import tseslint from 'typescript-eslint';

// ESLint 10 reads this file only. typescript-eslint 8.72 still peers
// TypeScript <6.1, so the recommended set stays non-type-checked.
// eslint-plugin-react has no release that peers ESLint 10.
export default tseslint.config(
  { ignores: ['dist/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['src/**/*.{ts,tsx}'],
    languageOptions: {
      parserOptions: {
        ecmaFeatures: {
          jsx: true,
        },
      },
    },
  },
);
