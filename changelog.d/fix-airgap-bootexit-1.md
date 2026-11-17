### Fixed

- Air-gapped builds (`-tags noaws,noazure,nogcp`) no longer link the Azure and AWS SDKs through `server/boot_exit.go`: the Azure and AWS startup-error classification moved into `!noazure` / `!noaws` files with stubs for the tagged builds. Exit codes 75/78 and messages are unchanged.
