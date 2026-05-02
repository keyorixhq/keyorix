# Web Dashboard Deployment Guide

This guide covers deploying the Keyorix web dashboard in various environments.

## Prerequisites

- Node.js 18+ (for development)
- Docker and Docker Compose (for containerized deployment)
- Nginx (for production deployment)

## Development Deployment

### Local Development

1. Install dependencies:
```bash
npm install
```

2. Start development server:
```bash
npm run dev
```

The application will be available at `http://localhost:3000`.

### Development with Backend

1. Start the backend server on port 8080
2. The Vite dev server will proxy API requests to the backend

## Production Deployment

### Docker Deployment

1. Build the Docker image:
```bash
docker build -t keyorix-web .
```

2. Run with Docker Compose:
```bash
docker-compose up -d
```

### Manual Deployment

1. Build the application:
```bash
npm run build
```

2. Copy the `dist` folder to your web server
3. Configure your web server to serve the static files and proxy API requests

### Nginx Configuration

Use the provided `nginx.conf` file or adapt it for your needs:

```nginx
server {
    listen 80;
    root /path/to/dist;
    index index.html;

    # API proxy
    location /api/ {
        proxy_pass http://backend:8080/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # SPA routing
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

## Environment Configuration

### Environment Variables

Create a `.env` file for environment-specific configuration:

```env
VITE_API_BASE_URL=http://localhost:8080/api
VITE_APP_NAME=Keyorix
VITE_APP_VERSION=1.0.0
VITE_ENABLE_ANALYTICS=false
```

### Build-time Configuration

The application uses Vite's environment variable system. Variables prefixed with `VITE_` are available in the client code.

## Security Considerations

### Content Security Policy

The nginx configuration includes a CSP header. Adjust it based on your security requirements:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';
```

### HTTPS Configuration

For production, always use HTTPS. Configure SSL certificates in your reverse proxy or load balancer.

### API Security

Ensure the backend API is properly secured with:
- Authentication tokens
- CORS configuration
- Rate limiting
- Input validation

## Monitoring and Logging

### Health Checks

The application includes a health check endpoint at `/health`.

### Logging

- Nginx access and error logs
- Application console logs (in development)
- Error tracking with services like Sentry (configure in production)

### Metrics

Monitor key metrics:
- Response times
- Error rates
- User sessions
- API usage

## Performance Optimization

### Caching Strategy

- Static assets: 1 year cache
- API responses: Configured in React Query
- Service worker: Caches static assets and API responses

### Bundle Optimization

The build process includes:
- Code splitting by route and vendor
- Tree shaking for unused code
- Minification and compression
- Source maps for debugging

### CDN Integration

For better performance, serve static assets from a CDN:

1. Upload the `dist/assets` folder to your CDN
2. Update the base URL in the build configuration
3. Configure cache headers appropriately

## Troubleshooting

### Common Issues

1. **API requests failing**: Check CORS configuration and proxy settings
2. **Routes not working**: Ensure SPA routing is configured in your web server
3. **Assets not loading**: Check file paths and permissions
4. **Performance issues**: Enable gzip compression and check bundle size

### Debug Mode

Enable debug mode in development:

```env
VITE_DEBUG=true
```

This will show additional logging and development tools.

### Log Analysis

Check logs for common issues:

```bash
# Nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Docker logs
docker-compose logs -f web
```

## Backup and Recovery

### Database Backups

The web application doesn't store data directly, but ensure your backend database is backed up regularly.

### Configuration Backups

Backup your:
- Environment configuration files
- Nginx configuration
- Docker Compose files
- SSL certificates

## Scaling

### Horizontal Scaling

The web application is stateless and can be scaled horizontally:

1. Use a load balancer (nginx, HAProxy, or cloud load balancer)
2. Deploy multiple instances of the web container
3. Ensure session storage is handled by the backend

### Vertical Scaling

For single-instance deployments:
- Increase container memory and CPU limits
- Optimize nginx worker processes
- Enable HTTP/2 for better performance

## Updates and Maintenance

### Rolling Updates

For zero-downtime updates:

1. Build new Docker image
2. Update one instance at a time
3. Health check before proceeding to next instance

### Maintenance Mode

To enable maintenance mode:

1. Update nginx configuration to serve a maintenance page
2. Reload nginx configuration
3. Perform maintenance tasks
4. Restore normal configuration