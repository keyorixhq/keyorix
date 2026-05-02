# State Management with Zustand

This directory contains the client-side state management implementation using Zustand for the Keyorix web dashboard. The state management is organized into several specialized stores that handle different aspects of the application.

## Store Architecture

### 1. UI Store (`uiStore.ts`)
Manages UI-specific state and interactions.

**Features:**
- Sidebar open/close state
- Modal management with data passing
- Page navigation and breadcrumbs
- Bulk selection for lists/tables
- Right panel/drawer management
- Focus management and accessibility

**Key Methods:**
- `setSidebarOpen(open)` - Control sidebar visibility
- `openModal(modalId, data)` - Open modal with optional data
- `setSelectedItems(items)` - Manage bulk selections
- `toggleSelectedItem(item)` - Toggle individual item selection

### 2. Form Store (`formStore.ts`)
Comprehensive form state management with validation and auto-save.

**Features:**
- Multi-form management
- Field-level validation and error handling
- Dirty/touched state tracking
- Form metadata and submission state
- Auto-save functionality with localStorage
- Form draft persistence

**Key Methods:**
- `initializeForm(formId, initialValues, meta)` - Initialize a new form
- `setFieldValue(formId, fieldName, value)` - Update field value
- `setFieldError(formId, fieldName, error)` - Set field validation error
- `isFormValid(formId)` - Check form validation status
- `saveFormDraft(formId)` - Save form draft to localStorage

**Custom Hooks:**
- `useForm(formId)` - Complete form management
- `useFormField(formId, fieldName)` - Individual field management
- `useFormAutoSave(formId, onSave)` - Auto-save functionality

### 3. Preferences Store (`preferencesStore.ts`)
User preferences and settings management with persistence.

**Features:**
- Theme management (light/dark/system)
- Language and localization settings
- Timezone and date formatting
- Notification preferences
- UI preferences (compact mode, tooltips, etc.)
- Accessibility settings

**Key Methods:**
- `setTheme(theme)` - Change application theme
- `setLanguage(language)` - Change interface language
- `setNotificationSettings(settings)` - Update notification preferences
- `getFormattedDate(date)` - Format dates with user preferences

**Custom Hooks:**
- `useThemeEffect()` - Apply theme changes to DOM
- `useLanguageEffect()` - Apply language changes to DOM

### 4. App Store (`appStore.ts`)
Global application state and system-wide data.

**Features:**
- Application metadata (version, build info)
- Online/offline status tracking
- Server connectivity status
- Feature flags management
- Global loading states
- Dashboard statistics caching
- Global search state
- Command palette state
- Keyboard shortcuts management

**Key Methods:**
- `setOnlineStatus(isOnline)` - Update connectivity status
- `setFeature(feature, enabled)` - Toggle feature flags
- `setGlobalSearchOpen(open)` - Control global search
- `initialize(config)` - Initialize app with configuration

**Custom Hooks:**
- `useOnlineStatusEffect()` - Monitor network connectivity
- `useKeyboardShortcuts()` - Handle global keyboard shortcuts

### 5. Notification Store (`notificationStore.ts`)
Toast notifications and alert management.

**Features:**
- Toast notification queue
- Auto-removal for success/info notifications
- Read/unread state tracking
- Notification categorization
- Bulk operations (mark all read, clear all)

**Key Methods:**
- `addNotification(notification)` - Add new notification
- `markAsRead(id)` - Mark notification as read
- `getUnreadCount()` - Get count of unread notifications

### 6. Auth Store (`authStore.ts`)
Authentication state and user session management.

**Features:**
- User authentication state
- JWT token management
- Session persistence
- Auto token refresh
- Login/logout operations

## Usage Examples

### Basic Store Usage

```typescript
import { useUIStore, useFormStore, usePreferencesStore } from '../store';

// UI Store
const { sidebarOpen, setSidebarOpen, openModal } = useUIStore();

// Form Store
const form = useForm('login-form');
form.initialize({ email: '', password: '' });

// Preferences Store
const { theme, setTheme, language, setLanguage } = usePreferencesStore();
```

### Form Management

```typescript
import { useForm, useFormField } from '../store/formStore';

function MyForm() {
    const form = useForm('my-form');
    const emailField = useFormField('my-form', 'email');
    
    useEffect(() => {
        form.initialize({
            email: '',
            password: ''
        });
    }, []);
    
    const handleSubmit = () => {
        if (form.isValid()) {
            const values = form.getValues();
            // Submit form
        }
    };
    
    return (
        <form onSubmit={handleSubmit}>
            <input
                value={emailField.value || ''}
                onChange={(e) => emailField.setValue(e.target.value)}
                onBlur={() => emailField.setTouched()}
            />
            {emailField.error && <span>{emailField.error}</span>}
        </form>
    );
}
```

### Auto-save Form

```typescript
import { useFormAutoSave } from '../store/formStore';

function AutoSaveForm() {
    const form = useForm('auto-save-form');
    
    // Enable auto-save every 30 seconds
    useFormAutoSave('auto-save-form', async (values) => {
        await api.saveDraft(values);
    });
    
    useEffect(() => {
        form.initialize({ content: '' }, { autoSave: true });
        // Try to load existing draft
        form.loadDraft();
    }, []);
}
```

### Theme Management

```typescript
import { usePreferencesStore, useThemeEffect } from '../store/preferencesStore';

function ThemeProvider({ children }) {
    const { theme, setTheme } = usePreferencesStore();
    
    // Apply theme changes to DOM
    useThemeEffect();
    
    return (
        <div className={theme === 'dark' ? 'dark' : ''}>
            {children}
        </div>
    );
}
```

### Global Search

```typescript
import { useAppStore, useKeyboardShortcuts } from '../store/appStore';

function GlobalSearch() {
    const {
        globalSearchOpen,
        globalSearchQuery,
        setGlobalSearchOpen,
        setGlobalSearchQuery
    } = useAppStore();
    
    // Enable Cmd+K shortcut
    useKeyboardShortcuts();
    
    if (!globalSearchOpen) return null;
    
    return (
        <Modal onClose={() => setGlobalSearchOpen(false)}>
            <input
                value={globalSearchQuery}
                onChange={(e) => setGlobalSearchQuery(e.target.value)}
                placeholder="Search..."
            />
        </Modal>
    );
}
```

## Persistence

### Automatic Persistence
- **Preferences Store**: Automatically persists user preferences
- **Auth Store**: Persists authentication state
- **Form Store**: Auto-saves form drafts to localStorage

### Manual Persistence
- **UI Store**: No persistence (session-only state)
- **App Store**: No persistence (runtime state)
- **Notification Store**: No persistence (temporary notifications)

## DevTools Integration

All stores are configured with Zustand DevTools for debugging:

```typescript
// Enable in development
const store = create<State>()(
    devtools(
        (set, get) => ({
            // store implementation
        }),
        {
            name: 'store-name',
        }
    )
);
```

## Testing

Store tests are located in `__tests__/stores.test.ts` and cover:
- State initialization
- Action execution
- State persistence
- Custom hook behavior
- Integration scenarios

Run tests with:
```bash
npm run test -- src/store/__tests__/stores.test.ts
```

## Best Practices

1. **Store Separation**: Keep stores focused on specific domains
2. **Immutable Updates**: Always use Zustand's `set` function for updates
3. **Custom Hooks**: Create custom hooks for complex store interactions
4. **Type Safety**: Use TypeScript interfaces for all store state
5. **Testing**: Write comprehensive tests for store logic
6. **Performance**: Use selectors to prevent unnecessary re-renders

## Integration with Components

The stores integrate seamlessly with React components and other parts of the application:

- **API Layer**: Stores work with the API service layer for data fetching
- **React Query**: Complementary to React Query for server state
- **Routing**: UI store manages navigation state
- **i18n**: Preferences store manages language settings
- **Theme System**: Preferences store controls theme application

This state management architecture provides a robust, scalable foundation for the Keyorix web dashboard while maintaining simplicity and developer experience.