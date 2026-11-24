module github.com/keyorixhq/keyorix

go 1.27

toolchain go1.27.4

require (
	cloud.google.com/go/kms v1.37.0
	cloud.google.com/go/secretmanager v1.24.0
	filippo.io/age v1.3.2
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.24.0
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.15.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.5.0
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v1.5.1
	github.com/BurntSushi/toml v1.6.0
	github.com/anishathalye/porcupine v1.3.1
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/config v1.33.19
	github.com/aws/aws-sdk-go-v2/credentials v1.21.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.66.0
	github.com/aws/aws-sdk-go-v2/service/kms v1.63.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.114.10
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.51.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.52.0
	github.com/beevik/etree v1.8.1
	github.com/boombuler/barcode v1.1.1
	github.com/crewjam/saml v0.6.3
	github.com/digitorus/pkcs7 v0.0.0-20261104125046-a476de3098e4
	github.com/digitorus/timestamp v0.0.0-20260914073129-b4b58b92aa51
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/getkin/kin-openapi v0.153.0
	github.com/go-chi/chi/v5 v5.5.0
	github.com/go-chi/cors v1.2.2
	github.com/go-sql-driver/mysql v1.10.1
	github.com/go-webauthn/webauthn v0.18.2
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-tpm v0.9.8
	github.com/google/go-tpm-tools v0.4.11
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.27.0
	github.com/jackc/pgx/v5 v5.13.0
	github.com/keyorixhq/keyorix-sdks/go v0.3.0
	github.com/klauspost/compress v1.20.4
	github.com/mattermost/xml-roundtrip-validator v0.1.0
	github.com/nicksnyder/go-i18n/v2 v2.7.0
	github.com/pquerna/otp v1.5.0
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
	github.com/redis/go-redis/v9 v9.23.0
	github.com/russellhaering/goxmldsig v1.6.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	github.com/shirou/gopsutil/v4 v4.26.10
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.1.0
	github.com/stretchr/testify v1.12.1
	github.com/wneessen/go-mail v0.8.2
	go.mongodb.org/mongo-driver/v2 v2.10.0
	go.yaml.in/yaml/v2 v2.4.5
	go.yaml.in/yaml/v4 v4.0.0
	golang.org/x/crypto v0.59.0
	golang.org/x/net v0.62.0
	golang.org/x/oauth2 v0.38.0
	golang.org/x/sync v0.25.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	golang.org/x/text v0.44.0
	golang.org/x/time v0.16.0
	golang.org/x/tools v0.52.0
	google.golang.org/api v0.315.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261104224025-d1e00e9f33ab
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.12
	gorm.io/driver/postgres v1.6.3
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.31.2
	modernc.org/sqlite v1.62.0
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.24.4 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.3.1 // indirect
	cloud.google.com/go/compute/metadata v0.10.0 // indirect
	cloud.google.com/go/iam v1.15.1 // indirect
	cloud.google.com/go/longrunning v1.5.0 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.13.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.9 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.5 // indirect
	github.com/aws/smithy-go v1.28.9 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/ebitengine/purego v0.11.3 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v1.0.2 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.1 // indirect
	github.com/google/s2a-go v0.1.11 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.25 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.4 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-sqlite3 v1.14.53 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/pandatix/go-abnf v0.5.5 // indirect
	github.com/philhofer/fwd v1.2.1 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/power-devops/perfstat v0.0.0-20260805114148-88456608a4f6 // indirect
	github.com/prometheus/common v0.74.0 // indirect
	github.com/prometheus/procfs v0.23.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/objx v0.8.0 // indirect
	github.com/tinylib/msgp v1.6.5 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/scram v1.4.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.72.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.72.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/log v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.yaml.in/yaml/v3 v3.0.6 // indirect
	golang.org/x/mod v0.43.0 // indirect
	google.golang.org/genproto v0.0.0-20261012220534-4341edf3f941 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261012220534-4341edf3f941 // indirect
	modernc.org/libc v1.81.2 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.13.0 // indirect
)
