// webauthn_finish_ops_test.go wires the two WebAuthn "finish" ceremonies into
// opCatalog: REST POST /api/v1/auth/webauthn/register/finish (authenticated,
// adds a passkey) and REST POST /auth/webauthn/login/finish (public, the
// login-time second factor). Both were left StatusPending because driving
// go-webauthn's REAL cryptographic verification (CreateCredential/ValidateLogin)
// needs a genuinely valid, internally-consistent signed attestation/assertion —
// not something a hand-rolled fixture can produce (see
// internal/core/webauthn_spec_vectors_test.go's file doc for the same problem
// solved the same way at the core-call level). The fix is the real W3C spec
// test vectors (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256),
// reproduced verbatim from that file so both call sites stay byte-identical to
// a vector go-webauthn's own test suite also uses.
//
// Both vectors carry a FIXED, pre-signed challenge — the real BeginWebAuthnRegistration/
// BeginWebAuthnLogin endpoints mint their own random challenge, which would never
// match, so Setup writes the WebAuthnSession (and, for login, the WebAuthnCredential)
// row DIRECTLY via w.db — the same "prerequisite state, not the operation under
// test" precedent enrolMFADirect (opcatalog_test.go) already established for MFA.
package faultops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Spec test vector constants (NoneES256), reproduced verbatim from
// internal/core/webauthn_spec_vectors_test.go (itself reproduced verbatim from
// go-webauthn's own test suite: webauthn/login_test.go's
// testLoginSpecVectorNoneES256, webauthn/registration_test.go's
// testRegistrationSpecVectorNoneES256) — real recorded ceremony data for RPID
// "example.org", origin "https://example.org".
const (
	fuzzSpecLoginAuthenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
	fuzzSpecLoginClientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
	fuzzSpecLoginSignatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
	fuzzSpecCredentialIDHex           = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
	fuzzSpecLoginChallengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	fuzzSpecCredentialPubKeyHex       = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"

	fuzzSpecRegAttestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	fuzzSpecRegClientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
	fuzzSpecRegChallengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
)

// mustFuzzHexDecode decodes a fixed, compile-time-constant hex string. The
// panic path only fires if one of the constants above is ever mistyped —
// surfaced immediately (test binary init crashes) rather than producing a
// silently-wrong vector.
func mustFuzzHexDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("webauthn spec vector hex decode: %v", err))
	}
	return b
}

var (
	fuzzSpecCredIDBytes       = mustFuzzHexDecode(fuzzSpecCredentialIDHex)
	fuzzSpecPubKeyBytes       = mustFuzzHexDecode(fuzzSpecCredentialPubKeyHex)
	fuzzSpecLoginChallengeB64 = base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecLoginChallengeHex))
	fuzzSpecRegChallengeB64   = base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecRegChallengeHex))
)

// fuzzAdminUserID looks up the bootstrapped admin's ID directly. A local
// duplicate of a lookup PR #2392 (not yet merged as of this branch's base)
// also adds as faultAdminUserID in opcatalog_test.go — fold into that shared
// helper once both have landed, rather than keeping two copies.
func fuzzAdminUserID(w *faultWorld) (uint, error) {
	var u models.User
	if err := w.db.Where("username = ?", "faultadmin").First(&u).Error; err != nil {
		return 0, err
	}
	return u.ID, nil
}

// specWebAuthnUserHandle mirrors webauthnUser.WebAuthnID()'s 8-byte big-endian
// encoding (internal/core/webauthn.go) — needed to hand-build a SessionData
// whose UserID the library will accept as belonging to userID.
func specWebAuthnUserHandle(userID uint) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(userID))
	return b
}

// specRegistrationAttestationBody builds the JSON body FinishWebAuthnRegistration's
// handler expects for its "credential" field: the NoneES256 registration spec
// vector, parseable by protocol.ParseCredentialCreationResponseBytes.
func specRegistrationAttestationBody() ([]byte, error) {
	id := base64.RawURLEncoding.EncodeToString(fuzzSpecCredIDBytes)
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecRegAttestationObjectHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecRegClientDataJSONHex)),
		},
	}
	return json.Marshal(body)
}

// specLoginAssertionBody builds the JSON body FinishWebAuthnLogin's handler
// expects for its "credential" field: the NoneES256 login spec vector,
// parseable by protocol.ParseCredentialRequestResponseBytes.
func specLoginAssertionBody() ([]byte, error) {
	id := base64.RawURLEncoding.EncodeToString(fuzzSpecCredIDBytes)
	body := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecLoginAuthenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecLoginClientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(mustFuzzHexDecode(fuzzSpecLoginSignatureHex)),
		},
	}
	return json.Marshal(body)
}

// storeFuzzWebAuthnSession writes a WebAuthnSession row directly (bypassing the
// real Begin* endpoint, which would mint its own random challenge that could
// never match a fixed spec vector) and returns the plaintext token to echo
// back as "webauthn_session". Mirrors internal/core's own storeWebAuthnSession
// (unexported, cross-package) exactly: sha256-hex of a random token as
// TokenHash, JSON-marshaled SessionData as Data.
func storeFuzzWebAuthnSession(w *faultWorld, userID uint, purpose string, sd *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if err := w.db.Create(&models.WebAuthnSession{
		UserID:    userID,
		TokenHash: hex.EncodeToString(sum[:]),
		Purpose:   purpose,
		Data:      data,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}).Error; err != nil {
		return "", err
	}
	return token, nil
}

// seedFuzzSpecCredential stores the spec login vector's credential (ID + public
// key) as userID's registered passkey, with the Flags (UserPresent,
// BackupEligible) the vector's authenticatorData actually asserts — a mismatch
// there is its own rejection (go-webauthn's "Backup Eligible flag inconsistency"
// check), matching internal/core/webauthn_spec_vectors_test.go's seedSpecCredential.
func seedFuzzSpecCredential(w *faultWorld, userID uint) error {
	blob, err := json.Marshal(webauthn.Credential{
		ID:        fuzzSpecCredIDBytes,
		PublicKey: fuzzSpecPubKeyBytes,
		Flags:     webauthn.CredentialFlags{UserPresent: true, BackupEligible: true},
	})
	if err != nil {
		return err
	}
	return w.db.Create(&models.WebAuthnCredential{
		UserID:         userID,
		CredentialID:   fuzzSpecCredIDBytes,
		Name:           "fuzz-spec-passkey",
		CredentialBlob: blob,
		CreatedAt:      time.Now(),
	}).Error
}

func init() {
	opCatalog = append(opCatalog,
		operation{
			Key: "REST POST /api/v1/auth/webauthn/register/finish",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				adminID, err := fuzzAdminUserID(w)
				if err != nil {
					return nil, fmt.Errorf("setup faultAdminUserID: %w", err)
				}
				token, err := storeFuzzWebAuthnSession(w, adminID, "register", &webauthn.SessionData{
					Challenge:  fuzzSpecRegChallengeB64,
					UserID:     specWebAuthnUserHandle(adminID),
					CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
				})
				if err != nil {
					return nil, fmt.Errorf("setup storeFuzzWebAuthnSession: %w", err)
				}
				return token, nil
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				token := state.(string)
				credBody, err := specRegistrationAttestationBody()
				if err != nil {
					return opResult{}, err
				}
				st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/auth/webauthn/register/finish", map[string]any{
					"webauthn_session": token,
					"name":             "fuzz-passkey",
					"password":         faultAdminPassword,
					"credential":       json.RawMessage(credBody),
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
		operation{
			// Public, login-time route — the second factor after the password step,
			// mirroring the existing "REST POST /auth/mfa/verify" op's Setup shape
			// (a live MFAChallenge, not a bearer token).
			Key: "REST POST /auth/webauthn/login/finish",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				adminID, err := fuzzAdminUserID(w)
				if err != nil {
					return nil, fmt.Errorf("setup faultAdminUserID: %w", err)
				}
				if err := seedFuzzSpecCredential(w, adminID); err != nil {
					return nil, fmt.Errorf("setup seedFuzzSpecCredential: %w", err)
				}
				challenge, err := w.core.CreateMFAChallenge(ctx, adminID)
				if err != nil {
					return nil, fmt.Errorf("setup CreateMFAChallenge: %w", err)
				}
				token, err := storeFuzzWebAuthnSession(w, adminID, "login", &webauthn.SessionData{
					Challenge: fuzzSpecLoginChallengeB64,
					UserID:    specWebAuthnUserHandle(adminID),
				})
				if err != nil {
					return nil, fmt.Errorf("setup storeFuzzWebAuthnSession: %w", err)
				}
				return [2]string{challenge, token}, nil
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				st2 := state.([2]string)
				credBody, err := specLoginAssertionBody()
				if err != nil {
					return opResult{}, err
				}
				st, body, err := httpJSON(ctx, w, http.MethodPost, "/auth/webauthn/login/finish", map[string]any{
					"mfa_challenge":    st2[0],
					"webauthn_session": st2[1],
					"credential":       json.RawMessage(credBody),
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
	)
}
