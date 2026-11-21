### Security
- **The Kubernetes sync fetcher refuses an environment list that names one environment twice.**
  The server keeps environment names unique within a project, so a list that repeats a name is
  not an honest answer (a hostile or broken server). The fetcher used to resolve the name to the
  last id listed and read the secret from that environment; it now fails the lookup without
  listing or reading any secret.
