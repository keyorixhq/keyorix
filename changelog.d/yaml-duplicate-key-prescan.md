### Security
- **Duplicate keys in an imported or configured YAML file are rejected in linear time.** The YAML
  library takes O(n²) time and memory on a mapping that repeats a key and reports the error only
  afterwards: a 20 KB file allocated about 1.4 GB, which the 100 MiB import size cap does not
  bound (reported upstream at yaml/go-yaml#510). `keyorix secret import --format vault` and the
  Kubernetes sync agent config now parse to a node tree first and fail on the first duplicate.
  Files without duplicate keys decode exactly as before; operator-reachable only, there is no
  network path.
