#!/usr/bin/env bash
# Writes one go fuzz corpus file for FuzzParseResponse: a well-formed, UNSIGNED response
# with exactly one Assertion (one Subject/NameID, one Conditions). It passes the
# epilogue check and strictAssertionShape and is then refused by the library (no
# signature), the only branch where ParseResponse could return something other than
# the sanitized sentinel. No committed seed reaches that branch (see
# saml-parse-error-oracle.conf).
set -eu
dest=$1
xml='<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="https://keyorix.internal/auth/saml/corp/acs"><saml:Issuer>https://idp.example/entity</saml:Issuer><saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>https://idp.example/entity</saml:Issuer><saml:Subject><saml:NameID>user@corp.example</saml:NameID></saml:Subject><saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/></saml:Assertion></samlp:Response>'
b64=$(printf '%s' "$xml" | base64 | tr -d '\n')
printf 'go test fuzz v1\nstring("%s")\n' "$b64" >"$dest/orh2-unsigned-wellformed"
