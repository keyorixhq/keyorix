import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';

import App from './App';
import { queryClient } from './lib/queryClient';
import './index.css';

// Apply theme before first paint — prevent flash.
// Reads from Zustand persist key; handles system preference.
(function () {
    try {
        const stored = localStorage.getItem('keyorix-ui');
        const parsed = stored ? JSON.parse(stored) : null;
        const theme = parsed?.state?.theme ?? 'dark';
        const resolved = theme === 'system'
            ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
            : theme;
        document.documentElement.setAttribute('data-theme', resolved);
    } catch {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
})();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
