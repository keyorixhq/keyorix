module sdkdiff-driver-go

go 1.26.2

require github.com/keyorixhq/keyorix-sdks/go v0.0.0

// build-drivers.sh overrides this with the real SDK checkout via -modfile.
replace github.com/keyorixhq/keyorix-sdks/go => ../../../../../../../keyorix-sdks/go
