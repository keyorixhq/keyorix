/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL: string;
  readonly VITE_API_TIMEOUT: string;
  readonly VITE_APP_NAME: string;
  readonly VITE_APP_VERSION: string;
  readonly VITE_APP_DESCRIPTION: string;
  readonly VITE_ENVIRONMENT: 'development' | 'staging' | 'production';
  readonly VITE_ENABLE_DEBUG: string;
  readonly VITE_ENABLE_DEVTOOLS: string;
  readonly VITE_SESSION_TIMEOUT: string;
  readonly VITE_CLIPBOARD_CLEAR_TIMEOUT: string;
  readonly VITE_DEFAULT_LANGUAGE: string;
  readonly VITE_DEFAULT_THEME: 'light' | 'dark' | 'system';
  readonly VITE_ITEMS_PER_PAGE: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}