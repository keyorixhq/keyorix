{{/* Base name, overridable, truncated to the 63-char DNS limit. */}}
{{- define "kxsync.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kxsync.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "kxsync.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "kxsync.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "kxsync.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "kxsync.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kxsync.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "kxsync.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "kxsync.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "kxsync.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* The namespaces the agent is granted write access to (defaults to the release ns). */}}
{{- define "kxsync.targetNamespaces" -}}
{{- if .Values.targetNamespaces -}}{{ .Values.targetNamespaces | toJson }}{{- else -}}{{ list .Release.Namespace | toJson }}{{- end -}}
{{- end -}}
