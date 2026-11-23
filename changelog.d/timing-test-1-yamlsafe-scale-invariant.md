### Testing

- `TestUnmarshal_DistinctKeysLinear` (internal/yamlsafe) now asserts growth between 25000 and 100000 keys instead of a fixed 5 s limit, so a loaded CI runner no longer fails it while a quadratic decode still does. Five other tests with 100 ms to 1 s wall-clock limits got hang-detector margins.
