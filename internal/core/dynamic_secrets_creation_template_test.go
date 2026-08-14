// dynamic_secrets_creation_template_test.go — #G39 detection_idea: test
// validateCreationTemplate's denylist against the full universe of Postgres
// privilege-widening DDL it's supposed to cover, not spot checks.
package core

import "testing"

func TestValidateCreationTemplate_RejectsPrivilegeEscalationKeywords(t *testing.T) {
	dangerous := []string{
		"GRANT OPTION",
		"WITH GRANT",
		"WITH ADMIN OPTION",
		"SUPER",
		"SUPERUSER",
		"CREATEROLE",
		"CREATEDB",
		"REPLICATION",
		"BYPASSRLS",
	}
	for _, kw := range dangerous {
		t.Run(kw, func(t *testing.T) {
			tmpl := "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' " + kw + ";"
			if err := validateCreationTemplate("postgresql", tmpl); err == nil {
				t.Errorf("validateCreationTemplate must reject a template containing %q", kw)
			}
			// Case-insensitivity: the finding's own root cause is about keywords
			// being enumerated at all, not case handling, but the existing
			// strings.ToUpper(tmpl) comparison must still catch a lowercase form.
			lower := "create role \"{{name}}\" with login password '{{password}}' " + kw + ";"
			if err := validateCreationTemplate("postgresql", lower); err == nil {
				t.Errorf("validateCreationTemplate must reject a lowercase template containing %q", kw)
			}
		})
	}
}

func TestValidateCreationTemplate_AllowsOrdinaryTemplate(t *testing.T) {
	tmpl := `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`
	if err := validateCreationTemplate("postgresql", tmpl); err != nil {
		t.Errorf("an ordinary read-only-grant template must not be rejected: %v", err)
	}
}

func TestValidateCreationTemplate_NonSQLBackendsSkipped(t *testing.T) {
	// AWS STS uses creation_statements as a session-policy JSON, not SQL;
	// Kubernetes ignores it — neither should be scanned for SQL keywords.
	if err := validateCreationTemplate("aws-sts", `{"Effect":"Allow","Action":"SUPERUSER"}`); err != nil {
		t.Errorf("non-SQL backends must not be scanned: %v", err)
	}
}

func TestValidateCreationTemplate_EmptyTemplateAllowed(t *testing.T) {
	if err := validateCreationTemplate("postgresql", ""); err != nil {
		t.Errorf("an empty template must be allowed: %v", err)
	}
}
