#!/usr/bin/env bash
# lib-passwords.sh — shared password generation for the DAST rig.
#
# generate_compliant_password [forbidden_substring ...]
#
# Produces a password satisfying Keyorix's own ADR-025 password policy, read
# from internal/core/password_policy.go's DefaultPasswordPolicy() at the time
# this was written: MinLength 16, at least one uppercase letter, one
# lowercase letter, one digit, and one special character, and (via
# RejectPersonalInfo) must not contain the target account's own
# username/email-local-part/display-name words.
#
# The stored KEYORIX_ADMIN_PASSWORD on this box was plain `openssl rand -hex`
# (per the OLD .env.example instructions) for 10+ days -- lowercase-hex-only
# output can NEVER satisfy "uppercase + special", so /system/init silently
# rejected every bootstrap attempt and nobody noticed (empty `users` table).
# This generator guarantees all four character classes BY CONSTRUCTION (a
# fixed one-of-each-class prefix), not by trusting a large random sample to
# probably contain one of each -- and checks the caller's forbidden
# substrings (username/email/display-name words) itself rather than leaving
# that to chance, regenerating in the astronomically rare case of a
# collision.
generate_compliant_password() {
    local pw attempt=0
    while true; do
        attempt=$((attempt + 1))
        # "Aa1!" guarantees uppercase+lowercase+digit+special regardless of
        # what the random hex tail contains; the hex tail (0-9a-f) adds more
        # lowercase+digit and brings total length well past the 16-char floor.
        pw="Aa1!$(openssl rand -hex 24)"
        local collision=0
        local forbidden
        for forbidden in "$@"; do
            [ -z "$forbidden" ] && continue
            if printf '%s' "$pw" | grep -qi -- "$forbidden"; then
                collision=1
                break
            fi
        done
        if [ "$collision" = "0" ]; then
            printf '%s' "$pw"
            return 0
        fi
        if [ "$attempt" -ge 20 ]; then
            echo "generate_compliant_password: could not avoid forbidden substrings after 20 attempts" >&2
            return 1
        fi
    done
}
