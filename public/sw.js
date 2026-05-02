// Service Worker for Keyorix Web Dashboard
// Provides offline functionality, caching, and background sync

const CACHE_NAME = 'keyorix-v1';
const STATIC_CACHE_NAME = 'keyorix-static-v1';
const DYNAMIC_CACHE_NAME = 'keyorix-dynamic-v1';

// Resources to cache immediately
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/manifest.json',
    '/favicon.ico',
    // Add other static assets as needed
];

// API endpoints that can be cached
const CACHEABLE_API_PATTERNS = [
    /\/api\/dashboard\/stats$/,
    /\/api\/users\/search/,
    /\/api\/groups\/search/,
    /\/api\/admin\/stats$/,
];

// API endpoints that should never be cached
const NON_CACHEABLE_API_PATTERNS = [
    /\/api\/auth\//,
    /\/api\/secrets\/\d+$/, // Individual secret values
    /\/api\/sharing\/create$/,
    /\/api\/admin\/users\/\d+$/,
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
    console.log('[SW] Installing service worker');

    event.waitUntil(
        caches.open(STATIC_CACHE_NAME)
            .then((cache) => {
                console.log('[SW] Caching static assets');
                return cache.addAll(STATIC_ASSETS);
            })
            .then(() => {
                console.log('[SW] Static assets cached');
                return self.skipWaiting();
            })
            .catch((error) => {
                console.error('[SW] Failed to cache static assets:', error);
            })
    );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
    console.log('[SW] Activating service worker');

    event.waitUntil(
        caches.keys()
            .then((cacheNames) => {
                return Promise.all(
                    cacheNames.map((cacheName) => {
                        if (cacheName !== STATIC_CACHE_NAME &&
                            cacheName !== DYNAMIC_CACHE_NAME &&
                            cacheName !== CACHE_NAME) {
                            console.log('[SW] Deleting old cache:', cacheName);
                            return caches.delete(cacheName);
                        }
                    })
                );
            })
            .then(() => {
                console.log('[SW] Service worker activated');
                return self.clients.claim();
            })
    );
});

// Fetch event - handle network requests
self.addEventListener('fetch', (event) => {
    const { request } = event;
    const url = new URL(request.url);

    // Skip non-GET requests
    if (request.method !== 'GET') {
        return;
    }

    // Skip chrome-extension requests
    if (url.protocol === 'chrome-extension:') {
        return;
    }

    // Handle different types of requests
    if (url.pathname.startsWith('/api/')) {
        event.respondWith(handleApiRequest(request));
    } else if (url.pathname.match(/\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2)$/)) {
        event.respondWith(handleStaticAsset(request));
    } else {
        event.respondWith(handlePageRequest(request));
    }
});

// Handle API requests with caching strategy
async function handleApiRequest(request) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Check if this API endpoint should never be cached
    if (NON_CACHEABLE_API_PATTERNS.some(pattern => pattern.test(pathname))) {
        return handleNetworkFirst(request);
    }

    // Check if this API endpoint can be cached
    if (CACHEABLE_API_PATTERNS.some(pattern => pattern.test(pathname))) {
        return handleCacheFirst(request, DYNAMIC_CACHE_NAME, 5 * 60 * 1000); // 5 minutes
    }

    // Default to network first for API requests
    return handleNetworkFirst(request);
}

// Handle static assets with cache first strategy
async function handleStaticAsset(request) {
    return handleCacheFirst(request, STATIC_CACHE_NAME);
}

// Handle page requests with network first, fallback to cache
async function handlePageRequest(request) {
    try {
        // Try network first
        const networkResponse = await fetch(request);

        // Cache successful responses
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE_NAME);
            cache.put(request, networkResponse.clone());
        }

        return networkResponse;
    } catch (error) {
        // Network failed, try cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }

        // If no cache, return offline page or error
        return new Response(
            JSON.stringify({
                error: 'Network unavailable',
                message: 'Please check your internet connection and try again.',
                offline: true
            }),
            {
                status: 503,
                statusText: 'Service Unavailable',
                headers: {
                    'Content-Type': 'application/json',
                }
            }
        );
    }
}

// Cache first strategy with optional TTL
async function handleCacheFirst(request, cacheName, ttl = null) {
    try {
        const cache = await caches.open(cacheName);
        const cachedResponse = await cache.match(request);

        // Check if cached response is still valid
        if (cachedResponse && ttl) {
            const cachedDate = new Date(cachedResponse.headers.get('date') || 0);
            const now = new Date();
            if (now.getTime() - cachedDate.getTime() > ttl) {
                // Cache expired, remove it
                await cache.delete(request);
            } else {
                return cachedResponse;
            }
        } else if (cachedResponse) {
            return cachedResponse;
        }

        // No valid cache, fetch from network
        const networkResponse = await fetch(request);

        if (networkResponse.ok) {
            // Add timestamp header for TTL checking
            const responseToCache = new Response(networkResponse.body, {
                status: networkResponse.status,
                statusText: networkResponse.statusText,
                headers: {
                    ...Object.fromEntries(networkResponse.headers.entries()),
                    'date': new Date().toISOString(),
                }
            });

            cache.put(request, responseToCache.clone());
            return responseToCache;
        }

        return networkResponse;
    } catch (error) {
        // Network failed, try cache anyway
        const cache = await caches.open(cacheName);
        const cachedResponse = await cache.match(request);

        if (cachedResponse) {
            return cachedResponse;
        }

        throw error;
    }
}

// Network first strategy
async function handleNetworkFirst(request) {
    try {
        const networkResponse = await fetch(request);

        // Cache successful responses for future offline use
        if (networkResponse.ok) {
            const cache = await caches.open(DYNAMIC_CACHE_NAME);
            cache.put(request, networkResponse.clone());
        }

        return networkResponse;
    } catch (error) {
        // Network failed, try cache
        const cachedResponse = await caches.match(request);
        if (cachedResponse) {
            return cachedResponse;
        }

        throw error;
    }
}

// Background sync for offline actions
self.addEventListener('sync', (event) => {
    console.log('[SW] Background sync triggered:', event.tag);

    if (event.tag === 'background-sync') {
        event.waitUntil(handleBackgroundSync());
    }
});

// Handle background sync
async function handleBackgroundSync() {
    try {
        // Get pending actions from IndexedDB or localStorage
        const pendingActions = await getPendingActions();

        for (const action of pendingActions) {
            try {
                await fetch(action.url, {
                    method: action.method,
                    headers: action.headers,
                    body: action.body,
                });

                // Remove successful action
                await removePendingAction(action.id);

                // Notify client of success
                await notifyClients({
                    type: 'SYNC_SUCCESS',
                    action: action.type,
                });
            } catch (error) {
                console.error('[SW] Failed to sync action:', action, error);
            }
        }
    } catch (error) {
        console.error('[SW] Background sync failed:', error);
    }
}

// Get pending actions (mock implementation)
async function getPendingActions() {
    // In a real implementation, this would read from IndexedDB
    return [];
}

// Remove pending action (mock implementation)
async function removePendingAction(actionId) {
    // In a real implementation, this would remove from IndexedDB
    console.log('[SW] Removing pending action:', actionId);
}

// Notify all clients
async function notifyClients(message) {
    const clients = await self.clients.matchAll();
    clients.forEach(client => {
        client.postMessage(message);
    });
}

// Handle push notifications
self.addEventListener('push', (event) => {
    console.log('[SW] Push notification received');

    if (!event.data) {
        return;
    }

    const data = event.data.json();

    const options = {
        body: data.body,
        icon: '/favicon.ico',
        badge: '/favicon.ico',
        data: data.data,
        actions: data.actions || [],
        requireInteraction: data.requireInteraction || false,
        silent: data.silent || false,
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
    console.log('[SW] Notification clicked:', event.notification);

    event.notification.close();

    const data = event.notification.data;

    event.waitUntil(
        self.clients.matchAll().then((clients) => {
            // Check if there's already a window/tab open
            const existingClient = clients.find(client =>
                client.url.includes(self.location.origin)
            );

            if (existingClient) {
                // Focus existing window and navigate if needed
                existingClient.focus();
                if (data && data.url) {
                    existingClient.postMessage({
                        type: 'NAVIGATE',
                        url: data.url,
                    });
                }
            } else {
                // Open new window
                const url = data && data.url ? data.url : '/';
                self.clients.openWindow(url);
            }
        })
    );
});

// Handle messages from clients
self.addEventListener('message', (event) => {
    console.log('[SW] Message received:', event.data);

    const { type, payload } = event.data;

    switch (type) {
        case 'SKIP_WAITING':
            self.skipWaiting();
            break;

        case 'CACHE_INVALIDATE':
            handleCacheInvalidation(payload);
            break;

        case 'QUEUE_ACTION':
            handleActionQueue(payload);
            break;

        default:
            console.log('[SW] Unknown message type:', type);
    }
});

// Handle cache invalidation
async function handleCacheInvalidation(payload) {
    try {
        const { pattern, cacheName } = payload;
        const cache = await caches.open(cacheName || DYNAMIC_CACHE_NAME);
        const keys = await cache.keys();

        const keysToDelete = keys.filter(key => {
            return new RegExp(pattern).test(key.url);
        });

        await Promise.all(
            keysToDelete.map(key => cache.delete(key))
        );

        console.log('[SW] Cache invalidated:', keysToDelete.length, 'entries');
    } catch (error) {
        console.error('[SW] Cache invalidation failed:', error);
    }
}

// Handle action queuing for offline support
async function handleActionQueue(payload) {
    try {
        // In a real implementation, this would store in IndexedDB
        console.log('[SW] Action queued for background sync:', payload);

        // Register for background sync
        await self.registration.sync.register('background-sync');
    } catch (error) {
        console.error('[SW] Failed to queue action:', error);
    }
}

// Periodic background sync (if supported)
self.addEventListener('periodicsync', (event) => {
    console.log('[SW] Periodic sync triggered:', event.tag);

    if (event.tag === 'cache-cleanup') {
        event.waitUntil(handleCacheCleanup());
    }
});

// Handle cache cleanup
async function handleCacheCleanup() {
    try {
        const cache = await caches.open(DYNAMIC_CACHE_NAME);
        const keys = await cache.keys();

        // Remove old entries (older than 24 hours)
        const now = new Date();
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours

        for (const key of keys) {
            const response = await cache.match(key);
            if (response) {
                const cachedDate = new Date(response.headers.get('date') || 0);
                if (now.getTime() - cachedDate.getTime() > maxAge) {
                    await cache.delete(key);
                }
            }
        }

        console.log('[SW] Cache cleanup completed');
    } catch (error) {
        console.error('[SW] Cache cleanup failed:', error);
    }
}