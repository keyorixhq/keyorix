### Changed
- **Unknown keys in the k8ssync agent config are now rejected.** The agent used to ignore a key
  it did not know, so a typo such as `prune_on_revok:` left it running with the default. It now
  refuses to start with an error that names the key and its line (never the value). A config that
  carries extra keys today must have them removed; the keys the agent reads are `keyorix_url`,
  `project_id`, `interval`, `health_port`, `cleanup`, `prune_on_revoke`, `on_suspend`,
  `mass_prune_ack` and `mappings` (each with `ref`, `namespace`, `name`, `key`). The shipped Helm
  chart, `docs/k8s-sync.md` and the e2e config only use these keys.
