package cryptoinventory

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CBOMOptions tunes CBOM output. The zero value is valid: a random serial number
// and the inventory's own generation time are used.
type CBOMOptions struct {
	SerialNumber  string // urn:uuid:...; random when empty
	Timestamp     time.Time
	ServerVersion string
}

// CycloneDX 1.6 document shapes. Only the fields this export uses are modelled.
type (
	cdxBOM struct {
		BomFormat    string         `json:"bomFormat"`
		SpecVersion  string         `json:"specVersion"`
		SerialNumber string         `json:"serialNumber"`
		Version      int            `json:"version"`
		Metadata     cdxMetadata    `json:"metadata"`
		Components   []cdxComponent `json:"components"`
	}
	cdxMetadata struct {
		Timestamp  string        `json:"timestamp"`
		Component  cdxMetaComp   `json:"component"`
		Properties []cdxProperty `json:"properties"`
	}
	cdxMetaComp struct {
		Type    string `json:"type"`
		BomRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
	}
	cdxProperty struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	cdxComponent struct {
		Type             string        `json:"type"`
		BomRef           string        `json:"bom-ref"`
		Name             string        `json:"name"`
		Description      string        `json:"description,omitempty"`
		CryptoProperties cdxCrypto     `json:"cryptoProperties"`
		Properties       []cdxProperty `json:"properties,omitempty"`
	}
	cdxCrypto struct {
		AssetType   string          `json:"assetType"`
		Algorithm   *cdxAlgorithm   `json:"algorithmProperties,omitempty"`
		Certificate *cdxCertificate `json:"certificateProperties,omitempty"`
		Related     *cdxRelated     `json:"relatedCryptoMaterialProperties,omitempty"`
	}
	cdxAlgorithm struct {
		Primitive      string   `json:"primitive"`
		ParameterSet   string   `json:"parameterSetIdentifier,omitempty"`
		Curve          string   `json:"curve,omitempty"`
		Mode           string   `json:"mode,omitempty"`
		CryptoFuncs    []string `json:"cryptoFunctions,omitempty"`
		ClassicalLevel *int     `json:"classicalSecurityLevel,omitempty"`
		NistQuantum    *int     `json:"nistQuantumSecurityLevel,omitempty"`
	}
	cdxCertificate struct {
		SubjectName  string `json:"subjectName,omitempty"`
		IssuerName   string `json:"issuerName,omitempty"`
		NotBefore    string `json:"notValidBefore,omitempty"`
		NotAfter     string `json:"notValidAfter,omitempty"`
		SigAlgRef    string `json:"signatureAlgorithmRef,omitempty"`
		KeyAlgRef    string `json:"subjectPublicKeyRef,omitempty"`
		CertFormat   string `json:"certificateFormat,omitempty"`
		CertFileType string `json:"certificateExtension,omitempty"`
	}
	// cdxRelated has no `value` field on purpose: the CBOM never carries key material.
	cdxRelated struct {
		Type         string `json:"type"`
		State        string `json:"state,omitempty"`
		AlgorithmRef string `json:"algorithmRef,omitempty"`
		Created      string `json:"creationDate,omitempty"`
		Expires      string `json:"expirationDate,omitempty"`
		Size         int    `json:"size,omitempty"`
	}
)

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func assetRef(id string) string { return "keyorix:asset:" + id }

func algoRef(a Asset) string {
	return "keyorix:algo:" + strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(a.Algorithm), "-"), "-")
}

// CBOM renders the inventory as a CycloneDX 1.6 JSON document: one
// cryptographic-asset component per inventory asset, plus one algorithm component
// per distinct algorithm that the asset components reference. Quantum-risk results
// ride along as `keyorix:*` component properties.
func (inv Inventory) CBOM(opts CBOMOptions) ([]byte, error) {
	serial := opts.SerialNumber
	if serial == "" {
		var err error
		if serial, err = newSerial(); err != nil {
			return nil, err
		}
	}
	ts := opts.Timestamp
	if ts.IsZero() {
		ts = inv.GeneratedAt
	}
	bom := cdxBOM{
		BomFormat: "CycloneDX", SpecVersion: "1.6", SerialNumber: serial, Version: 1,
		Metadata: cdxMetadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Component: cdxMetaComp{Type: "application", BomRef: "keyorix", Name: "Keyorix", Version: opts.ServerVersion},
			Properties: []cdxProperty{
				{"keyorix:quantum-horizon", inv.Policy.Horizon.UTC().Format("2006-01-02")},
				{"keyorix:migration-years", fmt.Sprint(inv.Policy.MigrationYears)},
				{"keyorix:unbounded-lifetime-years", fmt.Sprint(inv.Policy.UnboundedLifetimeYears)},
			},
		},
		Components: []cdxComponent{},
	}

	algos := map[string]cdxComponent{}
	for _, a := range inv.Assets {
		ref := algoRef(a)
		if _, ok := algos[ref]; !ok {
			algos[ref] = algorithmComponent(a, ref)
		}
		sigRef := ""
		if a.Certificate != nil && a.Certificate.SignatureAlgorithm != "" {
			sigRef = sigAlgoRef(a.Certificate.SignatureAlgorithm)
			if _, ok := algos[sigRef]; !ok {
				algos[sigRef] = signatureAlgorithmComponent(a.Certificate.SignatureAlgorithm, sigRef)
			}
		}
		bom.Components = append(bom.Components, assetComponent(a, ref, sigRef))
	}
	refs := make([]string, 0, len(algos))
	for r := range algos {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, r := range refs {
		bom.Components = append(bom.Components, algos[r])
	}
	return json.MarshalIndent(bom, "", "  ")
}

// sigAlgoRef is the bom-ref of the algorithm a certificate was signed with. It has
// its own prefix so it can never collide with a key algorithm's keyorix:algo: ref.
func sigAlgoRef(name string) string {
	return "keyorix:sigalg:" + strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-")
}

// signatureAlgorithmComponent is the algorithm component a certificate's
// signatureAlgorithmRef points at (for example ECDSA-SHA256 or SHA256-RSA).
func signatureAlgorithmComponent(name, ref string) cdxComponent {
	return cdxComponent{
		Type: "cryptographic-asset", BomRef: ref, Name: name,
		CryptoProperties: cdxCrypto{AssetType: "algorithm", Algorithm: &cdxAlgorithm{
			Primitive: "signature", CryptoFuncs: cryptoFuncs("signature"),
		}},
	}
}

// assetComponent renders one asset. algRef is the asset's own (key) algorithm
// component; sigRef is the certificate's signature algorithm component, empty when
// the asset is not a certificate or its signature algorithm is unknown.
func assetComponent(a Asset, algRef, sigRef string) cdxComponent {
	c := cdxComponent{
		Type: "cryptographic-asset", BomRef: assetRef(a.ID), Name: a.Name, Description: a.Notes,
		Properties: []cdxProperty{
			{"keyorix:class", string(a.Class)},
			{"keyorix:storage", a.Storage},
			{"keyorix:quantum-risk-score", fmt.Sprint(a.Risk.Score)},
			{"keyorix:quantum-risk-level", a.Risk.Level},
			{"keyorix:quantum-vulnerable", fmt.Sprint(a.Risk.QuantumVulnerable)},
			{"keyorix:risk-reasons", strings.Join(a.Risk.Reasons, "; ")},
		},
	}
	if a.CreatedAtEstimated {
		c.Properties = append(c.Properties, cdxProperty{"keyorix:created-at-estimated", "true"})
	}
	if a.Certificate != nil {
		ci := a.Certificate
		c.CryptoProperties = cdxCrypto{AssetType: "certificate", Certificate: &cdxCertificate{
			SubjectName: ci.SubjectName, IssuerName: ci.IssuerName,
			NotBefore: ci.NotBefore.UTC().Format(time.RFC3339), NotAfter: ci.NotAfter.UTC().Format(time.RFC3339),
			SigAlgRef: sigRef, CertFormat: "X.509",
		}}
		// subjectPublicKeyRef needs a key component, which the CBOM does not model;
		// the certified key's algorithm is linked by property instead.
		c.Properties = append(c.Properties, cdxProperty{"keyorix:key-algorithm-ref", algRef})
		return c
	}
	rel := &cdxRelated{Type: relatedType(a), State: "active", AlgorithmRef: algRef, Size: a.KeySizeBits}
	if a.CreatedAt != nil {
		rel.Created = a.CreatedAt.UTC().Format(time.RFC3339)
	}
	if a.ExpiresAt != nil {
		rel.Expires = a.ExpiresAt.UTC().Format(time.RFC3339)
	}
	c.CryptoProperties = cdxCrypto{AssetType: "related-crypto-material", Related: rel}
	return c
}

func relatedType(a Asset) string {
	switch a.Class {
	case ClassKEK, ClassDEK, ClassSigningKey, ClassAuditHMACKey:
		return "secret-key"
	case ClassWebAuthn, ClassJWTKey, ClassSAMLCertificate, ClassDatabaseTLSCert:
		return "public-key"
	case ClassBackupEncryption:
		return "other"
	case ClassRecoveryKey:
		return "digest"
	default:
		return "key"
	}
}

func algorithmComponent(a Asset, ref string) cdxComponent {
	alg := &cdxAlgorithm{Primitive: a.Primitive, CryptoFuncs: cryptoFuncs(a.Primitive)}
	if a.Primitive == "hash" {
		// For a hash the identifier is the digest length (SHA-256 -> "256"), not the
		// size of the secret it verifies (the recovery key is 260 bits).
		alg.ParameterSet = digestBits(a.Algorithm)
	} else if a.KeySizeBits > 0 {
		alg.ParameterSet = fmt.Sprint(a.KeySizeBits)
	}
	if a.Certificate != nil {
		alg.Curve = a.Certificate.Curve
	}
	if strings.Contains(strings.ToUpper(a.Algorithm), "GCM") {
		alg.Mode = "gcm"
	}
	switch {
	case a.PostQuantum:
		// no NIST level claimed without a verified parameter set
	case a.Asymmetric:
		zero := 0 // NIST category 0: no post-quantum security category is met
		alg.NistQuantum = &zero
	case strings.HasPrefix(a.Algorithm, "AES-") && a.KeySizeBits > 0:
		lvl := map[int]int{128: 1, 192: 3, 256: 5}[a.KeySizeBits]
		bits := a.KeySizeBits
		alg.ClassicalLevel, alg.NistQuantum = &bits, &lvl
	}
	if alg.Primitive == "" {
		alg.Primitive = "unknown"
	}
	return cdxComponent{
		Type: "cryptographic-asset", BomRef: ref, Name: a.Algorithm,
		CryptoProperties: cdxCrypto{AssetType: "algorithm", Algorithm: alg},
	}
}

// digestBits returns the digest length in a hash name such as "SHA-256" or
// "SHA3-512", or "" when the name does not end in one (the field is then omitted).
func digestBits(name string) string {
	parts := strings.Split(name, "-")
	if last := parts[len(parts)-1]; len(parts) > 1 {
		if _, err := strconv.Atoi(last); err == nil {
			return last
		}
	}
	return ""
}

func cryptoFuncs(primitive string) []string {
	switch primitive {
	case "ae", "pke":
		return []string{"encrypt", "decrypt"}
	case "mac":
		return []string{"tag"}
	case "kdf":
		return []string{"keyderive"}
	case "signature":
		return []string{"sign", "verify"}
	case "hash":
		return []string{"digest"}
	}
	return nil
}

// newSerial returns a random RFC 4122 version-4 UUID URN.
func newSerial() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate CBOM serial number: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
