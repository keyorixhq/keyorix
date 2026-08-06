{{/* Base name, overridable, truncated to the 63-char DNS limit. */}}
{{- define "kxop.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kxop.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "kxop.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kxop.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "kxop.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kxop.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kxop.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kxop.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kxop.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "kxop.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/*
kxop.scope resolves the operator's effective namespace scope ONCE, from
rbac.clusterScoped and watchNamespaces (ADR-076) -- rbac.yaml and deployment.yaml both
`include` this and `fromYaml` the result, rather than each independently branching on
the same two values. That independent-branching shape is exactly how #1224 produced a
silent no-RBAC-binding misrender: fixing it here means there is exactly one place that
decides "cluster" vs "namespaces", not two that must be kept in sync by hand.

Returns YAML the caller parses with `fromYaml` into a dict with:
  mode:       "cluster" | "namespaces"
  namespaces: (list, only when mode == "namespaces") -- ALWAYS populated with at least
              one entry when mode is "namespaces": the explicit watchNamespaces list, or
              [.Release.Namespace] when that's empty (ADR-076's own-namespace default).
              Never empty in this mode, so consuming templates need no further
              "namespaces happens to be empty" branch of their own.
  flag:       the exact manager CLI flag to render verbatim in deployment.yaml's args
              (-all-namespaces, or -watch-namespaces=a,b,c).

The fourth, contradictory combination (rbac.clusterScoped=true AND watchNamespaces set)
is a hard `fail` naming both values -- ADR-076 rejects resolving it by precedence, since
precedence-based resolution of exactly this contradiction is what #1224 got wrong.
*/}}
{{- define "kxop.scope" -}}
{{- if and .Values.rbac.clusterScoped .Values.watchNamespaces -}}
{{- fail (printf "keyorix-operator: rbac.clusterScoped=true and watchNamespaces=%s are both set -- these are mutually exclusive (ADR-076). Set exactly one: rbac.clusterScoped=true for a cluster-wide instance, or watchNamespaces for a bounded multi-namespace instance. Leave both unset/false for the namespace-scoped default (this release's own namespace only)." (toJson .Values.watchNamespaces)) -}}
{{- else if .Values.rbac.clusterScoped -}}
mode: cluster
flag: "-all-namespaces"
{{- else -}}
{{- $namespaces := .Values.watchNamespaces | default (list .Release.Namespace) -}}
mode: namespaces
namespaces: {{ toJson $namespaces }}
flag: {{ printf "-watch-namespaces=%s" (join "," $namespaces) | quote }}
{{- end -}}
{{- end -}}
