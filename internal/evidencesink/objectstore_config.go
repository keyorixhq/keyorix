package evidencesink

// ObjectStoreConfig configures the S3-compatible object-storage target. Credentials
// are NOT taken here — they resolve via the standard AWS chain (AWS_ACCESS_KEY_ID /
// AWS_SECRET_ACCESS_KEY env vars, shared config, or instance/workload identity).
//
// Deliberately NOT build-tagged (unlike objectstore.go/objectstore_lean.go): both the
// real implementation and the lean stub's NewObjectStore take this same config type,
// and server/main.go constructs one unconditionally — a single untagged definition is
// the only way to avoid the two build variants drifting out of sync with each other.
type ObjectStoreConfig struct {
	Bucket       string // required — destination bucket
	Prefix       string // optional key prefix, e.g. "keyorix/evidence/"
	Region       string // bucket region (any value for some S3-compatible stores)
	Endpoint     string // optional custom endpoint for S3-compatible stores (MinIO/R2/…)
	UsePathStyle bool   // path-style addressing — required by MinIO and some gateways

	// LockMode opts into S3 Object Lock retention on each uploaded object: ""
	// (off), "governance", or "compliance". The bucket must have Object Lock enabled.
	LockMode string
	// LockRetainDays is the retention period in days applied from upload time.
	// Required (> 0) when LockMode is set.
	LockRetainDays int
	// LegalHold places an S3 Object Lock legal hold on each uploaded object — an
	// indefinite hold (no expiry) that blocks deletion/overwrite until a principal
	// with s3:PutObjectLegalHold explicitly clears it. Independent of LockMode; the
	// bucket must have Object Lock enabled.
	LegalHold bool
}
