### Fixed

- `admin restore` of an archive written on a host with a non-UTC offset (for example a v0.95.x archive with `+01:00` times) no longer leaves a database that a UTC host cannot read back ("unsupported Scan, storing driver.Value type string into type *time.Time"); restored times are stored in UTC.
