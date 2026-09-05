{{/* Base name, overridable, truncated to the 63-char DNS limit. */}}
{{- define "keyorix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "keyorix.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "keyorix.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "keyorix.server.fullname" -}}{{ printf "%s-server" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "keyorix.web.fullname" -}}{{ printf "%s-web" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- define "keyorix.postgresql.fullname" -}}{{ printf "%s-postgresql" (include "keyorix.fullname" .) | trunc 63 | trimSuffix "-" }}{{- end -}}

{{/* The Secret holding KEYORIX_MASTER_PASSWORD / KEYORIX_DB_PASSWORD / admin. */}}
{{- define "keyorix.secretName" -}}
{{- if .Values.auth.existingSecret -}}{{ .Values.auth.existingSecret }}{{- else -}}{{ include "keyorix.fullname" . }}{{- end -}}
{{- end -}}

{{/* Database host: the bundled Postgres service, or the external host. */}}
{{- define "keyorix.dbHost" -}}
{{- if .Values.postgresql.enabled -}}{{ include "keyorix.postgresql.fullname" . }}{{- else -}}{{ required "externalDatabase.host is required when postgresql.enabled is false" .Values.externalDatabase.host }}{{- end -}}
{{- end -}}

{{- define "keyorix.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "keyorix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "keyorix.server.image" -}}
{{- if .Values.server.image.digest -}}
{{- printf "%s@%s" .Values.server.image.repository .Values.server.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.server.image.repository (default .Chart.AppVersion .Values.server.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "keyorix.web.image" -}}
{{- if .Values.web.image.digest -}}
{{- printf "%s@%s" .Values.web.image.repository .Values.web.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.web.image.repository (default .Chart.AppVersion .Values.web.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
nginx's add_header does NOT merge/inherit across nesting levels: if a location
block defines even one add_header of its own, every add_header inherited from
the enclosing http/server block is silently dropped for that location, not
just individually overridden. web-config.yaml's http{} block sets these as
baseline security headers, but several location blocks also set their own
add_header (CORS, Cache-Control, health-check Content-Type) for other
purposes, which would otherwise strip all of these from those responses. This
template is the single source of truth; every location block that defines its
own add_header must also include this so the headers still apply there.
*/}}
{{- define "keyorix.web.securityHeaders" -}}
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none';" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Opener-Policy "same-origin" always;
{{- end -}}
