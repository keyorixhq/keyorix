### Testing
- **Edge unattended tests reach only the server they started (#4356).** The install asks for port 0 and the helpers read each start's own listening line, instead of reusing a port picked once and closed, which another process of a CI job could take between restarts.
