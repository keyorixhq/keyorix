package faultops

import "github.com/keyorixhq/keyorix/internal/storage/models"

// worldExtraModels are tables the faultops worlds migrate and snapshot although
// models.AllTestModels() does not list them. That list is held to models.go's struct
// set by TestAllTestModels_MatchesModelsGoStructSet (internal/storage), so a model
// declared in another file of the package cannot be added there. Without this a
// world has no such table (the MFA reset ops failed with "no such table:
// mfa_reset_requests") or, if only migrated, oracle (a) could not see the table change.
//
// Add a model here only when it lives outside models.go and an opCatalog op writes it.
var worldExtraModels = []any{
	&models.MFAResetRequest{}, // internal/storage/models/mfa_reset.go (RECOVERY-MFA-RESET-1, #3751)
}

// worldModels is every model a faultops world migrates and snapshots.
func worldModels() []any {
	return append(models.AllTestModels(), worldExtraModels...)
}
