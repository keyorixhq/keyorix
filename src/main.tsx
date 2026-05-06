import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClientProvider } from '@tanstack/react-query';

import App from './App';
import { queryClient } from './lib/queryClient';
import './index.css';

// Apply theme before first paint to prevent flash.
// Reads from the same localStorage key that Zustand persist uses.
(function () {
    try {
        const stored = localStorage.getItem('keyorix-ui');
        const parsed = stored ? JSON.parse(stored) : null;
        const theme = parsed?.state?.theme ?? 'dark';
        document.documentElement.setAttribute('data-theme', theme);
    } catch {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
})();

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
