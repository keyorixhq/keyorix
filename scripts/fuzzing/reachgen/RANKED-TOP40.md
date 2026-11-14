# reachgen — third-party entry points Keyorix actually calls on untrusted input

Total distinct third-party exported funcs called: 496. Shown: top 40 UNCOVERED entries with at least one untrusted-provenance call site.

| # | Module | Package | Function | Sites | Untrusted | Provenance | Fuzzable |
|---|--------|---------|----------|------:|----------:|------------|:--------:|
| 1 | github.com/go-chi/chi/v5 | · | `URLParam(*http.Request, string)` | 181 | 181 | request-body×181 | no |
| 2 | github.com/stretchr/testify | mock | `Mock.Called([]interface{})` | 354 | 45 | request-body×44, config×1 | no |
| 3 | github.com/go-chi/chi/v5 | · | `Router.Post(string, http.HandlerFunc)` | 135 | 24 | config×24 | no |
| 4 | google.golang.org/protobuf | internal/impl | `Export.MessageStateOf(impl.Pointer)` | 318 | 14 | config×14 | no |
| 5 | google.golang.org/protobuf | runtime/protoimpl | `Pointer` | 318 | 14 | config×14 | no |
| 6 | github.com/go-chi/chi/v5 | · | `Router.Get(string, http.HandlerFunc)` | 171 | 14 | config×14 | no |
| 7 | gorm.io/gorm | migrator | `Migrator.RunWithValue(interface{}, func(*gorm.Statement) error)` | 13 | 11 | request-body×9, backend-response×6 | no |
| 8 | golang.org/x/crypto | bcrypt | `CompareHashAndPassword([]byte, []byte)` | 9 | 9 | request-body×9 | yes |
| 9 | google.golang.org/protobuf | internal/impl | `Export.MessageStringOf(protoreflect.ProtoMessage)` | 159 | 7 | config×7 | no |
| 10 | google.golang.org/protobuf | internal/impl | `MessageInfo.MessageOf(any)` | 159 | 7 | config×7 | no |
| 11 | github.com/jackc/pgx/v5 | stdlib | `OpenDB(pgx.ConnConfig, []stdlib.OptionOpenDB)` | 6 | 6 | request-body×1, config×6, backend-response×2 | no |
| 12 | golang.org/x/crypto | hkdf | `New(func() hash.Hash, []byte, []byte, []byte)` | 6 | 6 | request-body×6 | no |
| 13 | github.com/prometheus/client_golang | prometheus | `MustNewConstMetric(*prometheus.Desc, prometheus.ValueType, float64, []string)` | 15 | 5 | backend-response×5 | no |
| 14 | github.com/go-chi/chi/v5 | · | `Mux.Use([]func(http.Handler) http.Handler)` | 12 | 5 | config×5 | no |
| 15 | github.com/aws/aws-sdk-go-v2 | aws | `ToString(*string)` | 8 | 5 | request-body×5, config×3, backend-response×2 | no |
| 16 | github.com/aws/aws-sdk-go-v2/config | · | `LoadDefaultConfig(context.Context, []func(*config.LoadOptions) error)` | 5 | 4 | request-body×1, config×1, backend-response×4 | no |
| 17 | github.com/go-chi/chi/v5 | middleware | `GetReqID(context.Context)` | 4 | 4 | request-body×4 | no |
| 18 | gorm.io/gorm | migrator | `Migrator.GuessConstraintInterfaceAndTable(*gorm.Statement, string)` | 4 | 4 | request-body×4 | no |
| 19 | github.com/go-chi/chi/v5 | · | `Router.With([]func(http.Handler) http.Handler)` | 293 | 3 | config×3 | no |
| 20 | gorm.io/gorm | · | `Migrator.HasColumn(interface{}, string)` | 16 | 3 | request-body×1, config×2 | no |
| 21 | github.com/go-chi/chi/v5 | · | `Mux.Get(string, http.HandlerFunc)` | 6 | 3 | config×3 | no |
| 22 | gorm.io/gorm | schema | `Schema.LookUpField(string)` | 6 | 3 | request-body×3 | yes |
| 23 | golang.org/x/time | rate | `Limit` | 5 | 3 | config×3 | no |
| 24 | go.mongodb.org/mongo-driver/v2 | mongo | `Database.RunCommand(context.Context, any, []options.Lister[options.RunCmdOptions])` | 3 | 3 | request-body×3 | no |
| 25 | gorm.io/gorm | schema | `Schema.LookIndex(string)` | 3 | 3 | request-body×3 | yes |
| 26 | github.com/go-chi/chi/v5 | · | `Router.Delete(string, http.HandlerFunc)` | 37 | 2 | config×2 | no |
| 27 | gorm.io/gorm | · | `Migrator.AddColumn(interface{}, string)` | 17 | 2 | config×2 | no |
| 28 | github.com/go-chi/chi/v5 | · | `Router.Use([]func(http.Handler) http.Handler)` | 11 | 2 | config×2 | no |
| 29 | github.com/aws/aws-sdk-go-v2/config | · | `WithRegion(string)` | 4 | 2 | request-body×1, config×1 | yes |
| 30 | google.golang.org/protobuf | types/known/wrapperspb | `Int64(int64)` | 4 | 2 | request-body×2 | yes |
| 31 | github.com/go-chi/chi/v5 | · | `Mux.Route(string, func(r chi.Router))` | 2 | 2 | config×2 | no |
| 32 | github.com/golang-jwt/jwt/v5 | · | `Parser.ParseWithClaims(string, jwt.Claims, jwt.Keyfunc)` | 2 | 2 | request-body×2 | no |
| 33 | github.com/google/go-tpm | tpm2 | `Marshal(tpm2.Marshallable)` | 2 | 2 | request-body×2 | no |
| 34 | github.com/jackc/pgx/v5 | · | `ParseConfigWithOptions(string, pgx.ParseConfigOptions)` | 2 | 2 | request-body×2, config×2 | no |
| 35 | github.com/jackc/pgx/v5 | pgconn | `ParseConfigWithOptions(string, pgconn.ParseConfigOptions)` | 2 | 2 | request-body×2, config×2 | no |
| 36 | github.com/jackc/pgx/v5 | pgxpool | `NewWithConfig(context.Context, *pgxpool.Config)` | 2 | 2 | request-body×1, config×2, backend-response×2 | no |
| 37 | github.com/nicksnyder/go-i18n/v2 | i18n | `Localizer.Localize(*i18n.LocalizeConfig)` | 2 | 2 | request-body×2, config×2 | no |
| 38 | github.com/prometheus/client_golang | prometheus | `NewCounterFunc(prometheus.CounterOpts, func() float64)` | 2 | 2 | config×2 | no |
| 39 | github.com/prometheus/client_golang | prometheus | `NewGaugeFunc(prometheus.GaugeOpts, func() float64)` | 2 | 2 | config×2 | no |
| 40 | github.com/prometheus/client_golang | prometheus/promhttp | `HandlerFor(prometheus.Gatherer, promhttp.HandlerOpts)` | 2 | 2 | config×2 | no |
