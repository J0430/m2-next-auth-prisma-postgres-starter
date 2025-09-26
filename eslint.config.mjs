// eslint.config.mjs
import tseslint from 'typescript-eslint';

export default [
  // JS/TS parser + TS plugin
  ...tseslint.config({
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      // browser + node globals so “no-undef” doesn’t whine about FormData, React, process, etc.
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        FormData: 'readonly',
        HTMLFormElement: 'readonly',
        HTMLInputElement: 'readonly',
        React: 'readonly',
        process: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
    },
  }),

  // Ignore generated/build artifacts
  { ignores: ['.next/**', 'node_modules/**', '**/*.d.ts'] },
];