# Testing Infrastructure

This directory contains the testing infrastructure for the web dashboard application.

## Overview

The testing setup includes:

- **Vitest** for unit and integration testing
- **React Testing Library** for component testing
- **Playwright** for end-to-end testing
- **Custom utilities** for enhanced testing experience

## Structure

```
src/test/
├── README.md           # This file
├── setup.ts           # Global test setup and configuration
├── utils.tsx          # Custom render functions and utilities
├── mocks.ts           # Mock data and API mocks
├── form-helpers.ts    # Form testing utilities
├── i18n-test.ts       # Test-specific i18n configuration
└── infrastructure.test.ts  # Tests for the testing infrastructure itself
```

## Running Tests

### Unit/Integration Tests (Vitest)

```bash
# Run tests once
npm run test:run

# Run tests in watch mode
npm run test:watch

# Run tests with UI
npm run test:ui

# Run tests with coverage
npm run test:coverage
```

### End-to-End Tests (Playwright)

```bash
# Run e2e tests
npm run e2e

# Run e2e tests with UI
npm run e2e:ui

# Run e2e tests in headed mode (visible browser)
npm run e2e:headed

# Debug e2e tests
npm run e2e:debug

# View test report
npm run e2e:report
```

## Custom Render Functions

### Basic Render

```typescript
import { render, screen } from '@/test/utils';

test('should render component', () => {
  render(<MyComponent />);
  expect(screen.getByText('Hello')).toBeInTheDocument();
});
```

### Render with Custom Query Client

```typescript
import { renderWithQueryClient } from '@/test/utils';
import { QueryClient } from '@tanstack/react-query';

test('should render with custom query client', () => {
  const queryClient = new QueryClient();
  renderWithQueryClient(<MyComponent />, queryClient);
});
```

### Render without Router

```typescript
import { renderWithoutRouter } from '@/test/utils';

test('should render component without router', () => {
  renderWithoutRouter(<MyComponent />);
});
```

## Mock Data

### Using Mock Data

```typescript
import { mockUser, mockSecrets, mockShares } from '@/test/mocks';

test('should use mock data', () => {
  expect(mockUser.username).toBe('testuser');
  expect(mockSecrets).toHaveLength(3);
});
```

### Setting up Mocks

```typescript
import { setupMocks, cleanupMocks } from '@/test/mocks';

beforeEach(() => {
  setupMocks();
});

afterEach(() => {
  cleanupMocks();
});
```

## Form Testing Helpers

### Basic Form Interactions

```typescript
import { formHelpers } from '@/test/form-helpers';

test('should fill and submit form', async () => {
  render(<LoginForm />);
  
  await formHelpers.fillInput('Email', 'test@example.com');
  await formHelpers.fillInput('Password', 'password123');
  await formHelpers.submitForm('Login');
});
```

### Complex Form Testing

```typescript
import { formHelpers, asyncFormHelpers } from '@/test/form-helpers';

test('should handle form validation', async () => {
  render(<SecretForm />);
  
  await formHelpers.fillSecretForm({
    name: 'test-secret',
    value: 'secret-value',
    type: 'password',
    namespace: 'production'
  });
  
  await asyncFormHelpers.submitAndWaitForSuccess();
});
```

### Accessibility Testing

```typescript
import { accessibilityHelpers } from '@/test/form-helpers';

test('should have proper accessibility', () => {
  render(<MyForm />);
  
  accessibilityHelpers.expectProperLabels(['Email', 'Password']);
  accessibilityHelpers.expectProperAria('Email');
});
```

## Best Practices

### 1. Use Custom Render Functions

Always use the custom render functions from `@/test/utils` instead of the default ones from React Testing Library. They provide necessary providers and context.

### 2. Mock External Dependencies

Use the provided mocks for localStorage, clipboard, and other browser APIs. Add new mocks to `mocks.ts` as needed.

### 3. Test User Interactions

Focus on testing user interactions rather than implementation details:

```typescript
// Good
await userEvent.click(screen.getByRole('button', { name: 'Submit' }));

// Avoid
fireEvent.click(screen.getByTestId('submit-button'));
```

### 4. Use Semantic Queries

Prefer semantic queries that reflect how users interact with your app:

```typescript
// Good
screen.getByRole('button', { name: 'Submit' })
screen.getByLabelText('Email')
screen.getByText('Welcome')

// Avoid
screen.getByTestId('submit-btn')
screen.getByClassName('email-input')
```

### 5. Test Error States

Always test both success and error scenarios:

```typescript
test('should handle form submission error', async () => {
  // Mock API to return error
  mockApiClient.post.mockRejectedValue(new Error('Network error'));
  
  render(<MyForm />);
  await formHelpers.submitForm();
  
  expect(screen.getByText('Network error')).toBeInTheDocument();
});
```

### 6. Clean Up After Tests

The setup automatically handles cleanup, but for custom mocks:

```typescript
afterEach(() => {
  vi.clearAllMocks();
});
```

## Configuration

### Vitest Configuration

The Vitest configuration is in `vite.config.ts`:

- Uses jsdom environment for DOM testing
- Includes global test utilities
- Excludes e2e tests from unit test runs
- Enables CSS processing for styled components

### Playwright Configuration

The Playwright configuration is in `playwright.config.ts`:

- Tests multiple browsers (Chrome, Firefox, Safari)
- Includes mobile viewport testing
- Automatically starts dev server
- Captures screenshots and videos on failure

## Troubleshooting

### Common Issues

1. **Tests hanging**: Make sure to use `--run` flag for CI or one-time runs
2. **Mock not working**: Ensure mocks are set up in `beforeEach` hooks
3. **Router errors**: Use appropriate render function with or without router
4. **Async issues**: Use `waitFor` for async operations

### Debug Tips

1. Use `screen.debug()` to see current DOM state
2. Use `--ui` flag to run tests in interactive mode
3. Check browser console in Playwright tests with `page.on('console', console.log)`
4. Use `test.only` to run specific tests during development

## Adding New Tests

### Unit/Component Tests

1. Create test files next to components: `Component.test.tsx`
2. Use the custom render functions
3. Test user interactions and accessibility
4. Mock external dependencies

### E2E Tests

1. Add tests to the `e2e/` directory
2. Use page object pattern for complex flows
3. Test critical user journeys
4. Keep tests independent and atomic

### Integration Tests

1. Test multiple components working together
2. Mock API responses appropriately
3. Test data flow and state management
4. Verify error handling and edge cases