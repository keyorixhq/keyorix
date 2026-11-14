- **INV-FUZZCLOUD-aws-fail-closed-non-2xx** An aws-sdk-go-v2 operation, as Keyorix
  constructs its client (static/chain credentials + BaseEndpoint override), must return
  an error — never a populated output — when the endpoint replies with any HTTP status
  outside [200,300), for BOTH wire protocols Keyorix decodes: awsJson1_1 (KMS) and
  REST-XML (S3). Why: a hostile or MITM'd KMS/S3 endpoint returning a 4xx/5xx that was
  treated as success would let an empty/attacker body look like a successful KEK
  wrap or a successful WORM evidence upload (`internal/crypto/awskms`,
  `internal/evidencesink`). Guard: `FuzzKMSResponse` (`fuzz/thirdparty/awskms`,
  DescribeKey/Encrypt/Decrypt) and `FuzzS3PutObjectResponse` (`fuzz/thirdparty/awss3`,
  PutObject) assert error-on-non-2xx plus a no-retry-storm and no-cross-host-redirect
  tripwire; red/green-proven by planting a fail-open that swallows the SDK error. Does
  NOT verify the Keyorix-layer empty-CiphertextBlob rejection (awskms's own unit test)
  or any crypto correctness. Related: [[INV-FUZZCLOUD-no-sent-credential-in-error]].
