// command_census_test.go — FINISH-SPLIT step 3 (docs/cli-split-inventory.md §9). Walks the
// old CLI's actual cobra tree (rootCmd, this package) and checks every leaf command against
// a hand-maintained classification map. This is the CI gate that keeps the split's inventory
// from drifting silently: a leaf command with no entry here fails the build immediately,
// rather than surfacing later as a surprise when someone tries to delete the old CLI (Phase 5)
// or the /system proxy tier (PR 14).
//
// Every leaf must be classified as one of:
//   - censusMoved      -- has a home in the thin CLI (cli/cmd), ref names the PR.
//   - censusMovedAdmin -- has a home in keyorix-server admin, ref names the PR/B-phase.
//   - censusMovedOut   -- has a home in a separate tool (e.g. keyorix-migrate).
//   - censusDropped    -- deliberately not carried forward; note names the reason.
//   - censusGap        -- known, tracked, NOT YET decided or built. This is not a silent
//     skip (CLAUDE.md: "a skip with a wrong reason is worse than no skip") -- it's a
//     reasoned, visible placeholder, same shape as contracttest's pendingRegistry. Every
//     censusGap entry is exactly what FINISH-SPLIT step 3 reports to the coordinator as
//     "the unmapped list," and it gates PR 14 / Phase 5 (see TestNoGapsRemain, skipped by
//     default -- flip -run to include it once every gap is resolved).
//
// Regenerate docs/cli-split-inventory.md §9 with:
//
//	KEYORIX_CENSUS_REGEN=1 go test ./internal/cli/ -run TestCLICommandCensus
package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

type censusStatus int

const (
	censusMoved censusStatus = iota
	censusMovedAdmin
	censusMovedOut
	censusDropped
	censusGap
)

func (s censusStatus) String() string {
	switch s {
	case censusMoved:
		return "moved (thin CLI)"
	case censusMovedAdmin:
		return "moved (keyorix-server admin)"
	case censusMovedOut:
		return "moved out (separate tool)"
	case censusDropped:
		return "dropped"
	case censusGap:
		return "GAP (unresolved)"
	default:
		return "unknown"
	}
}

type censusEntry struct {
	status censusStatus
	ref    string // PR/phase reference, or the drop/gap reason
	note   string // optional extra detail
}

// commandCensus classifies every leaf command in the old CLI's cobra tree (256 as of
// 2026-09-24; see the census dump in the FINISH-SPLIT step 3 PR description for how this
// was derived: walk rootCmd, diff against the thin CLI's and admin's own trees, classify
// every command absent from both by hand). Keyed by the leaf's full space-joined command
// path (e.g. "secret create", "rbac assign-role-to-group").
var commandCensus = map[string]censusEntry{
	"access-review":                      {censusMoved, "PR 7, #2069", "the bare command (GET /projects/{id}/access-review report), distinct from its attest/revoke/campaign subcommands"},
	"access-review attest":               {censusMoved, "PR 7, #2069", ""},
	"access-review campaign close":       {censusMoved, "PR 7, #2069", ""},
	"access-review campaign decide":      {censusMoved, "PR 7, #2069", ""},
	"access-review campaign list":        {censusMoved, "PR 7, #2069", ""},
	"access-review campaign open":        {censusMoved, "PR 7, #2069", ""},
	"access-review campaign show":        {censusMoved, "PR 7, #2069", ""},
	"access-review revoke":               {censusMoved, "PR 7, #2069", ""},
	"anomalies acknowledge":              {censusMoved, "PR 7, #2069", ""},
	"anomalies config get":               {censusMoved, "PR 7, #2069", ""},
	"anomalies config set":               {censusMoved, "PR 7, #2069", ""},
	"anomalies escalation create":        {censusMoved, "PR 7, #2069", ""},
	"anomalies escalation delete":        {censusMoved, "PR 7, #2069", ""},
	"anomalies escalation list":          {censusMoved, "PR 7, #2069", ""},
	"anomalies escalation run":           {censusMoved, "PR 7, #2069", ""},
	"anomalies list":                     {censusMoved, "PR 7, #2069", ""},
	"audit checkpoint":                   {censusMoved, "PR 7, #2069", ""},
	"audit export":                       {censusMoved, "PR 7, #2069", ""},
	"audit logs":                         {censusMoved, "PR 7, #2069", ""},
	"audit migrate-chain-encoding":       {censusMoved, "PR 7, #2069", ""},
	"audit search":                       {censusMoved, "PR 7, #2069", ""},
	"audit verify":                       {censusMoved, "PR 7, #2069", "REST-only; distinct from keyorix-server admin's new verify-audit (B4, #2039), which verifies OFFLINE without trusting the running server"},
	"auth login":                         {censusMoved, "PR 0, #2019", "renamed to top-level `login`"},
	"auth logout":                        {censusMoved, "PR 2, #2030", "renamed to top-level `logout`"},
	"auth mfa stepup":                    {censusMoved, "PR 2, #2030", "renamed to top-level `mfa stepup`"},
	"auth status":                        {censusMoved, "PR 0, #2019", "folded into top-level `status`, which now shows server/login state directly"},
	"billing report":                     {censusGap, "unassigned", "dual-mode REST route exists (GET /admin/billing/report); not in any split PR's scope; Finding S17 (embedded mode has no userID param to authorize against)"},
	"break-glass activate":               {censusMoved, "PR 1, #2043", ""},
	"break-glass list":                   {censusMoved, "PR 1, #2043", ""},
	"break-glass revoke":                 {censusMoved, "PR 1, #2043", ""},
	"bundle build":                       {censusDropped, "maintainer-only tooling (decision 2026-09-24)", "offline release-signing tool; stays as internal tooling outside the public CLI"},
	"bundle import":                      {censusGap, "PR 10 leftovers, in progress", "verification code is moving into pkg/bundleverify (no core/storage/config/SDK imports); flips to censusMoved once that PR lands"},
	"bundle verify":                      {censusGap, "PR 10 leftovers, in progress", "verification code is moving into pkg/bundleverify (no core/storage/config/SDK imports); flips to censusMoved once that PR lands"},
	"compliance controls":                {censusMoved, "PR 8, #2069", ""},
	"compliance credential-trends":       {censusMoved, "PR 8, #2069", ""},
	"compliance digest":                  {censusMoved, "PR 8, #2069", ""},
	"compliance export":                  {censusMoved, "PR 8, #2069", ""},
	"compliance inventory":               {censusMoved, "PR 8, #2069", ""},
	"compliance permission-baseline":     {censusMoved, "PR 8, #2069", ""},
	"compliance permission-changes":      {censusMoved, "PR 8, #2069", ""},
	"compliance report":                  {censusMoved, "PR 8, #2069", ""},
	"compliance rotation-by-backend":     {censusMoved, "PR 8, #2069", ""},
	"compliance verify":                  {censusMoved, "PR 8, #2069", ""},
	"config set-remote":                  {censusDropped, "ADR-108 §4", "superseded by the single credstore mechanism; local/embedded config-switching removed entirely"},
	"config status":                      {censusDropped, "ADR-108 §4", "superseded by the single credstore mechanism"},
	"config test-connection":             {censusDropped, "ADR-108 §4", "superseded by the single credstore mechanism"},
	"config use-local":                   {censusDropped, "ADR-108 §4", "local/embedded mode does not exist in the thin CLI (ADR-108 Decision A)"},
	"connect":                             {censusDropped, "ADR-108 Decision A", "the bare command (connect to a server); superseded by `login`"},
	"connect disconnect":                 {censusDropped, "ADR-108 Decision A", "embedded-mode connect/disconnect has no meaning once local mode is removed"},
	"connect status":                     {censusDropped, "ADR-108 Decision A", "superseded by top-level `status`"},
	"dynamic-secret classify":            {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret create":              {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret get-config":          {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret issue":               {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret leases":              {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret list":                {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret renew":               {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret revoke":              {censusMoved, "PR 1, #2043", ""},
	"dynamic-secret revoke-all":          {censusMoved, "PR 1, #2043", ""},
	"encryption auth-encryption enable":  {censusMovedAdmin, "B3, #2034", ""},
	"encryption auth-encryption migrate": {censusMovedAdmin, "B3, #2034", ""},
	"encryption auth-encryption rotate":  {censusMovedAdmin, "B3, #2034", ""},
	"encryption auth-encryption status":  {censusMovedAdmin, "B3, #2034", ""},
	"encryption auth-encryption validate": {censusMovedAdmin, "B3, #2034", ""},
	"encryption fix-perms":                {censusMovedAdmin, "B3, #2034", ""},
	"encryption init":                     {censusMovedAdmin, "B3, #2034", ""},
	"encryption migrate-provider":         {censusMovedAdmin, "B3, #2034", "the bare command (the actual re-wrap operation), distinct from its `cleanup` subcommand"},
	"encryption migrate-provider cleanup": {censusMovedAdmin, "B3, #2034", ""},
	"encryption rotate":                   {censusMovedAdmin, "B3, #2034", ""},
	"encryption rotate-kek":               {censusMovedAdmin, "B3, #2034", ""},
	"encryption shamir-split":             {censusMovedAdmin, "B3, #2034", "the inventory flagged this as CLIENT-ONLY-eligible (pure crypto, no DB/config import); bundled into admin encryption for operational simplicity -- confirmed deliberate, not an oversight, by reading server/admin/encryption.go directly"},
	"encryption status":                   {censusMovedAdmin, "B3, #2034", ""},
	"encryption upgrade-aad":              {censusMovedAdmin, "B3, #2034", ""},
	"encryption validate":                 {censusMovedAdmin, "B3, #2034", ""},
	"group add-member":                    {censusMoved, "PR 3, #2044", ""},
	"group create":                        {censusMoved, "PR 3, #2044", ""},
	"group delete":                        {censusMoved, "PR 3, #2044", ""},
	"group get":                           {censusMoved, "PR 3, #2044", ""},
	"group list":                          {censusMoved, "PR 3, #2044", ""},
	"group members":                       {censusMoved, "PR 3, #2044", ""},
	"group remove-member":                 {censusMoved, "PR 3, #2044", ""},
	"group update":                        {censusMoved, "PR 3, #2044", ""},
	"hygiene":                             {censusMoved, "PR 8, #2069", ""},
	"invite list":                         {censusMoved, "PR 3, #2044", ""},
	"invite resend":                       {censusMoved, "PR 3, #2044", ""},
	"invite revoke":                       {censusMoved, "PR 3, #2044", ""},
	"invite send":                         {censusMoved, "PR 3, #2044", ""},
	"legal-hold lift":                     {censusMoved, "PR 8, #2069", ""},
	"legal-hold place":                    {censusMoved, "PR 8, #2069", ""},
	"legal-hold status":                   {censusMoved, "PR 8, #2069", ""},
	"license install":                     {censusGap, "PR 10 leftovers, in progress", "verification code is moving into pkg/licenseverify (no core/storage/config/SDK imports); flips to censusMoved once that PR lands"},
	"license issue":                       {censusDropped, "maintainer-only tooling (decision 2026-09-24)", "offline license-signing tool; stays as internal tooling outside the public CLI"},
	"license status":                      {censusGap, "PR 10 leftovers, in progress", "verification code is moving into pkg/licenseverify (no core/storage/config/SDK imports); flips to censusMoved once that PR lands"},
	"machine audit":                       {censusMoved, "PR 2, #2030", ""},
	"machine binding add":                 {censusMoved, "PR 2, #2030", ""},
	"machine binding list":                {censusMoved, "PR 2, #2030", ""},
	"machine binding rm":                  {censusMoved, "PR 2, #2030", ""},
	"machine create":                      {censusMoved, "PR 2, #2030", ""},
	"machine describe":                    {censusMoved, "PR 2, #2030", ""},
	"machine list":                        {censusMoved, "PR 2, #2030", ""},
	"machine reactivate":                  {censusMoved, "PR 2, #2030", ""},
	"machine revoke":                      {censusMoved, "PR 2, #2030", ""},
	"machine suspend":                     {censusMoved, "PR 2, #2030", ""},
	"machine token issue":                 {censusMoved, "PR 2, #2030", ""},
	"machine token list":                  {censusMoved, "PR 2, #2030", ""},
	"machine token revoke":                {censusMoved, "PR 2, #2030", ""},
	"machine token-hygiene":               {censusMoved, "PR 2, #2030", ""},
	"migrate user-to-machine":             {censusGap, "unassigned", "inventory recommends collapsing to a REST-backed thin-CLI command (route exists: POST /projects/{id}/machine-identities/migrate-from-user); not in any split PR's scope. NOT related to the separate keyorix-migrate tool (Vault/cloud import) despite the name collision"},
	"notification channel add":            {censusMoved, "PR 7, #2069", ""},
	"notification channel delete":         {censusMoved, "PR 7, #2069", ""},
	"notification channel get":            {censusMoved, "PR 7, #2069", ""},
	"notification channel list":           {censusMoved, "PR 7, #2069", ""},
	"notification channel update":         {censusMoved, "PR 7, #2069", ""},
	"pat cleanup-expired":                 {censusMoved, "PR 2, #2030", ""},
	"pat create":                          {censusMoved, "PR 2, #2030", ""},
	"pat hygiene":                         {censusMoved, "PR 2, #2030", ""},
	"pat list":                            {censusMoved, "PR 2, #2030", ""},
	"pat list-expired":                    {censusMoved, "PR 2, #2030", ""},
	"pat revoke":                          {censusMoved, "PR 2, #2030", ""},
	"project create":                      {censusMoved, "PR 6, #2049", ""},
	"project current":                     {censusMoved, "PR 6, #2049", ""},
	"project describe":                    {censusMoved, "PR 6, #2049", ""},
	"project env clone":                   {censusMoved, "PR 6, #2049", ""},
	"project env create":                  {censusMoved, "PR 6, #2049", ""},
	"project env delete":                  {censusMoved, "PR 6, #2049", ""},
	"project env list":                    {censusMoved, "PR 6, #2049", ""},
	"project environments":                {censusMoved, "PR 6, #2049", "legacy alias for `project env list`, kept for flag compatibility (conservative default, not a unilateral drop)"},
	"project health":                      {censusMoved, "PR 6, #2049", ""},
	"project hygiene":                     {censusMoved, "PR 6, #2049", ""},
	"project list":                        {censusMoved, "PR 6, #2049", ""},
	"project stats":                       {censusMoved, "PR 6, #2049", ""},
	"project use":                         {censusMoved, "PR 6, #2049", ""},
	"rbac assign-role":                    {censusMoved, "PR 3, #2044", ""},
	"rbac assign-role-to-group":           {censusMoved, "PR 3, #2044", ""},
	"rbac audit-logs":                     {censusMoved, "PR 3, #2044", ""},
	"rbac check-permission":               {censusMoved, "PR 3, #2044", ""},
	"rbac export-matrix":                  {censusMoved, "PR 3, #2044", ""},
	"rbac list-group-roles":               {censusMoved, "PR 3, #2044", ""},
	"rbac list-permissions":               {censusMoved, "PR 3, #2044", ""},
	"rbac list-roles":                     {censusMoved, "PR 3, #2044", ""},
	"rbac list-user-roles":                {censusMoved, "PR 3, #2044", ""},
	"rbac remove-role":                    {censusMoved, "PR 3, #2044", ""},
	"rbac remove-role-from-group":         {censusMoved, "PR 3, #2044", ""},
	"request access":                      {censusMoved, "PR 7, #2069", ""},
	"request bulk-approve":                {censusMoved, "PR 7, #2069", ""},
	"request bulk-reject":                 {censusMoved, "PR 7, #2069", ""},
	"request list":                        {censusMoved, "PR 7, #2069", ""},
	"request rejection-templates add":     {censusMoved, "PR 7, #2069", ""},
	"request rejection-templates delete":  {censusMoved, "PR 7, #2069", ""},
	"request rejection-templates list":    {censusMoved, "PR 7, #2069", ""},
	"request review":                      {censusMoved, "PR 7, #2069", ""},
	"request secret-access":               {censusMoved, "PR 7, #2069", ""},
	"request withdraw":                    {censusMoved, "PR 7, #2069", ""},
	"risk add":                            {censusMoved, "PR 8, #2069", ""},
	"risk approve":                        {censusMoved, "PR 8, #2069", ""},
	"risk list":                           {censusMoved, "PR 8, #2069", ""},
	"risk revoke":                         {censusMoved, "PR 8, #2069", ""},
	"rotation create":                     {censusMoved, "PR 1, #2043", ""},
	"rotation delete":                     {censusMoved, "PR 1, #2043", ""},
	"rotation list":                       {censusMoved, "PR 1, #2043", ""},
	"rotation order":                      {censusMoved, "PR 1, #2043", ""},
	"rotation plan":                       {censusMoved, "PR 1, #2043", ""},
	"rotation show":                       {censusMoved, "PR 1, #2043", ""},
	"rotation status":                     {censusMoved, "PR 1, #2043", ""},
	"run":                                 {censusGap, "PR 10 leftovers, in progress", "flips to censusMoved once that PR lands; the local/embedded fetch branch will be dropped, not ported -- Finding S18: it had zero authorization check and zero audit event, so dropping it is a security fix, not just cleanup"},
	"secret access":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret access-log":                   {censusMoved, "PR 4/5, #2069", ""},
	"secret acl grant":                    {censusMoved, "PR 4/5, #2069", ""},
	"secret acl list":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret acl revoke":                   {censusMoved, "PR 4/5, #2069", ""},
	"secret audit":                        {censusMoved, "PR 4/5, #2069", ""},
	"secret auto-rotate":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret blast-radius":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret bulk-delete":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret bulk-rename":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret bulk-rotate":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret cert":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret classify":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret clear-schedule":               {censusMoved, "PR 4/5, #2069", ""},
	"secret comment add":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret comment delete":               {censusMoved, "PR 4/5, #2069", ""},
	"secret comment list":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret copy":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret copy-environment":             {censusMoved, "PR 4/5, #2069", ""},
	"secret create":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret delete":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret deps add":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret deps impact":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret deps list":                    {censusMoved, "PR 4/5, #2069", ""},
	"secret deps rm":                      {censusMoved, "PR 4/5, #2069", ""},
	"secret description":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret diff":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret expiring":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret explain":                      {censusMoved, "PR 4/5, #2069", ""},
	"secret export":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret fix":                          {censusMoved, "PR 4/5, #2069", ""},
	"secret folder create":                {censusMoved, "PR 4/5, #2069", ""},
	"secret folder delete":                {censusMoved, "PR 4/5, #2069", ""},
	"secret folder list":                  {censusMoved, "PR 4/5, #2069", ""},
	"secret get":                          {censusMoved, "PR 4/5, #2069", ""},
	"secret get-schedule":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret import":                       {censusMoved, "PR 4/5, #2069", "cloud/Vault `--source` import stays dropped (SBOM goal); moves to keyorix-migrate instead (separate track)"},
	"secret info":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret list":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret move":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret name-conformance":             {censusMoved, "PR 4/5, #2069", ""},
	"secret orphaned":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret ownership-history":            {censusMoved, "PR 4/5, #2069", ""},
	"secret quota-report":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret reassign-owner":               {censusMoved, "PR 4/5, #2069", ""},
	"secret render":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret restore":                      {censusMoved, "PR 4/5, #2069", ""},
	"secret resume":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret rollback":                     {censusMoved, "PR 4/5, #2069", ""},
	"secret rotate":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret rotation-simulate":            {censusMoved, "PR 4/5, #2069", ""},
	"secret scan":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret score":                        {censusMoved, "PR 4/5, #2069", ""},
	"secret set-schedule":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret suspend":                      {censusMoved, "PR 4/5, #2069", ""},
	"secret tags":                         {censusMoved, "PR 4/5, #2069", ""},
	"secret template create":              {censusMoved, "PR 4/5, #2069", ""},
	"secret template delete":              {censusMoved, "PR 4/5, #2069", ""},
	"secret template get":                 {censusMoved, "PR 4/5, #2069", ""},
	"secret template list":                {censusMoved, "PR 4/5, #2069", ""},
	"secret trash":                        {censusMoved, "PR 4/5, #2069", ""},
	"secret update":                       {censusMoved, "PR 4/5, #2069", ""},
	"secret versions":                     {censusMoved, "PR 4/5, #2069", ""},
	"share create":                        {censusMoved, "PR 9, #2070 (open)", ""},
	"share group-shares":                  {censusMoved, "PR 9, #2070 (open)", ""},
	"share list":                          {censusMoved, "PR 9, #2070 (open)", ""},
	"share revoke":                        {censusMoved, "PR 9, #2070 (open)", ""},
	"share self-remove":                   {censusMoved, "PR 9, #2070 (open)", ""},
	"share shared-secrets":                {censusMoved, "PR 9, #2070 (open)", ""},
	"share update":                        {censusMoved, "PR 9, #2070 (open)", ""},
	"sod policy create":                   {censusMoved, "PR 8, #2069", ""},
	"sod policy delete":                   {censusMoved, "PR 8, #2069", ""},
	"sod policy list":                     {censusMoved, "PR 8, #2069", ""},
	"sod violations":                      {censusMoved, "PR 8, #2069", ""},
	"status":                              {censusMoved, "PR 0, #2019", "local/embedded status branch dropped (Finding S18-adjacent); remote-only, now also folds in `auth status`"},
	"system audit":                        {censusMovedAdmin, "B1, #2016", "folded into `admin validate`'s file-permission check"},
	"system info":                         {censusMoved, "PR 7/10, #2069", ""},
	"system init":                         {censusMovedAdmin, "B1, #2016", "the local-host half (create config/keys/DB) moved to `admin init`; the --server network-bootstrap half (POST /system/init, unauthenticated, bootstrap-token-gated) is NOT YET in the thin CLI -- tracked as a GAP, needs its own small PR"},
	"system role-expiry-check":            {censusMoved, "PR 7/10, #2069", ""},
	"system token-expiry-check":           {censusMoved, "PR 7/10, #2069", ""},
	"system validate":                     {censusMovedAdmin, "B1, #2016", ""},
	"trust keygen":                        {censusMoved, "PR 8, #2069", ""},
	"usage show":                          {censusGap, "unassigned", "dual-mode REST route exists (GET /admin/usage); not in any split PR's scope; Finding S17 (embedded mode has no userID param to authorize against)"},
	"user create":                         {censusMoved, "PR 6, #2049", ""},
	"user delete":                         {censusMoved, "PR 6, #2049", ""},
	"user force-password-reset":           {censusMoved, "PR 6, #2049", ""},
	"user get":                            {censusMoved, "PR 6, #2049", ""},
	"user list":                           {censusMoved, "PR 6, #2049", ""},
	"user reactivate":                     {censusMoved, "PR 6, #2049", ""},
	"user resend-setup-link":              {censusMoved, "PR 6, #2049", ""},
	"user revoke-sessions":                {censusMoved, "PR 6, #2049", ""},
	"user suspend":                        {censusMoved, "PR 6, #2049", ""},
	"user suspend-inactive":               {censusMoved, "PR 6, #2049", ""},
	"user update":                         {censusMoved, "PR 6, #2049", ""},
}

// TestCLICommandCensus is the CI gate: every leaf command in the old CLI's live cobra tree
// must have a commandCensus entry. A new command with no entry fails the build immediately --
// this is the mechanism that keeps FINISH-SPLIT's inventory honest as the old CLI keeps
// changing underneath it (CLAUDE.md: "prefer the machine-checked over the asserted").
func TestCLICommandCensus(t *testing.T) {
	leaves := walkLeafCommands(rootCmd)
	if len(leaves) == 0 {
		t.Fatal("walked zero leaf commands from rootCmd -- the walker or the tree is broken")
	}
	paths := make([]string, len(leaves))
	for i, l := range leaves {
		paths[i] = l.fullPath()
	}

	var unmapped []string
	for _, p := range paths {
		if _, ok := commandCensus[p]; !ok {
			unmapped = append(unmapped, p)
		}
	}
	sort.Strings(unmapped)
	for _, p := range unmapped {
		t.Errorf("unmapped command: %q -- add an entry to commandCensus (internal/cli/command_census_test.go)", p)
	}

	// Stale entries (a mapped command that no longer exists) are equally a drift risk --
	// report them too, so a deleted/renamed command's entry doesn't sit forever as a false
	// "still there" claim.
	live := make(map[string]bool, len(paths))
	for _, p := range paths {
		live[p] = true
	}
	var stale []string
	for k := range commandCensus {
		if !live[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("stale census entry: %q -- no longer a real command, remove it from commandCensus", s)
	}

	if os.Getenv("KEYORIX_CENSUS_REGEN") == "1" {
		writeCensusMarkdown(t, paths)
	}
}

// TestNoGapsRemain gates PR 14 (delete /system + RemoteStorage) and Phase 5 (delete the old
// CLI): both require every command to have a REAL home, not a tracked-but-open censusGap.
// Skipped by default -- this is meant to be run explicitly once the coordinator believes
// every gap is closed, not on every CI run (a censusGap is a known, reported state, not a
// build failure by itself; see the package doc comment).
func TestNoGapsRemain(t *testing.T) {
	if os.Getenv("KEYORIX_CENSUS_CHECK_GAPS") != "1" {
		t.Skip("set KEYORIX_CENSUS_CHECK_GAPS=1 to check for open gaps (PR 14 / Phase 5 gate)")
	}
	var gaps []string
	for k, v := range commandCensus {
		if v.status == censusGap {
			gaps = append(gaps, k)
		}
	}
	sort.Strings(gaps)
	for _, g := range gaps {
		t.Errorf("open gap blocks PR 14 / Phase 5: %q -- %s", g, commandCensus[g].note)
	}
}

// writeCensusMarkdown renders the current census as a markdown table to
// docs/cli-split-inventory-census.md (checked into the PR alongside the code, per the task's
// "commit its output to docs/cli-split-inventory.md §9" -- kept as a separate generated file
// and included by reference, rather than hand-editing a table into the middle of a hand-written
// doc on every regen).
func writeCensusMarkdown(t *testing.T, leaves []string) {
	t.Helper()
	sorted := append([]string(nil), leaves...)
	sort.Strings(sorted)

	var b strings.Builder
	b.WriteString("<!-- generated by: KEYORIX_CENSUS_REGEN=1 go test ./internal/cli/ -run TestCLICommandCensus -->\n")
	b.WriteString("<!-- do not hand-edit; edit internal/cli/command_census_test.go's commandCensus map instead -->\n\n")
	fmt.Fprintf(&b, "%d old-CLI leaf commands, all classified.\n\n", len(sorted))
	b.WriteString("| Command | Status | Reference | Note |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, l := range sorted {
		e := commandCensus[l]
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", l, e.status, e.ref, e.note)
	}

	gapCount := 0
	for _, e := range commandCensus {
		if e.status == censusGap {
			gapCount++
		}
	}
	fmt.Fprintf(&b, "\n**%d open gap(s)** (blocks PR 14 / Phase 5 -- see TestNoGapsRemain):\n\n", gapCount)
	for _, l := range sorted {
		if commandCensus[l].status == censusGap {
			fmt.Fprintf(&b, "- `%s`: %s\n", l, commandCensus[l].note)
		}
	}

	path := "../../docs/cli-split-inventory-census.md"
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil { // #nosec G304 -- fixed relative path, dev-only regen tool
		t.Fatalf("write census markdown: %v", err)
	}
	t.Logf("wrote %s", path)
}
