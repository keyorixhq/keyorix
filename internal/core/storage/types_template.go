package storage

// SecretTemplateFieldUpdate is the set of columns an edit of a secret template
// owns (#2700). Same reasoning as RotationPolicyFieldUpdate: all six come from
// the request, and the point is the exclusion of created_by/created_at.
type SecretTemplateFieldUpdate struct {
	Name                  string
	Description           string
	DefaultClassification string
	DefaultTags           string
	DescriptionPattern    string
	RotationHintDays      int
}
