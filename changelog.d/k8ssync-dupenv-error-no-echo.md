### Fixed
- The Kubernetes sync fetcher no longer puts a server-supplied environment name into the error it returns when the server lists one environment twice (the list is still refused). A fuzzer oracle found the echo after the duplicate-environment fix.
