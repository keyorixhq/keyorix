package storage

// RotationPolicyFieldUpdate is the set of columns an operator edit of a rotation
// policy owns (#2700). Every field is written, because core.UpdateRotationPolicy
// requires all six on its request — unlike SecretFieldUpdate there is no
// "leave this one alone" case to express. What matters is which columns are NOT
// here: rotation_state, last_rotation_error and last_state_at belong to the
// executor (UpdateRotationState), and a policy edit used to revert them.
type RotationPolicyFieldUpdate struct {
	Name            string
	Description     string
	IntervalDays    int
	AlertDaysBefore int
	NotifyOnBreach  bool
	IsActive        bool
}
