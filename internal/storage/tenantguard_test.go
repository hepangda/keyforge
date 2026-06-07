package storage_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// tenantOwnedTables are the tables every named query must scope by tenant_id
// to avoid cross-tenant data leakage. tenants itself is excluded (it owns
// the partition key) and schema_meta is a single-row settings table.
var tenantOwnedTables = []string{
	"users", "user_credentials",
	"clients", "client_redirect_uris",
	"jwks_keys",
}

// TestTenantGuard fails the build if any sqlc query against a tenant-owned
// table is missing a `tenant_id = $N` predicate. This is a structural test:
// even authors who forget the multi-tenancy rule cannot land such a query.
// Limited to SELECT/UPDATE/DELETE — INSERTs are checked separately for a
// tenant_id column in their column list.
//
// Queries that legitimately operate across tenants (kid is globally unique,
// background sweeps, internal transactional updates by primary key) may
// opt out by adding a leading SQL comment of the form
//
//	-- tenantguard: global-ok (reason)
//
// The reason should explain why cross-tenant operation is safe.
func TestTenantGuard(t *testing.T) {
	dir := sqlcQueriesDir(t)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read sqlc queries dir %s: %v", dir, err)
	}

	tenantRe := regexp.MustCompile(`(?i)tenant_id\s*=`)
	insertRe := regexp.MustCompile(`(?is)^\s*INSERT\s+INTO\s+(\w+)`)
	cmdRe := regexp.MustCompile(`(?is)^\s*(SELECT|UPDATE|DELETE)\b`)
	optOutRe := regexp.MustCompile(`(?i)--\s*tenantguard:\s*global-ok`)

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		for _, q := range splitQueries(string(b)) {
			body := q.body
			lower := strings.ToLower(body)
			isInsert := insertRe.MatchString(body)

			if isInsert {
				if m := insertRe.FindStringSubmatch(body); m != nil {
					table := strings.ToLower(m[1])
					if isTenantOwned(table) && !strings.Contains(lower, "tenant_id") {
						t.Errorf("query %q INSERTs into %s without tenant_id\n---\n%s",
							q.name, table, body)
					}
				}
				continue
			}

			if !cmdRe.MatchString(body) {
				continue
			}
			needsGuard := false
			for _, tbl := range tenantOwnedTables {
				if strings.Contains(lower, strings.ToLower(tbl)) {
					needsGuard = true
					break
				}
			}
			if needsGuard && !tenantRe.MatchString(body) && !optOutRe.MatchString(body) {
				t.Errorf("query %q touches a tenant-owned table without `tenant_id =` "+
					"and no `-- tenantguard: global-ok (reason)` opt-out:\n---\n%s",
					q.name, body)
			}
		}
	}
}

func isTenantOwned(table string) bool {
	for _, t := range tenantOwnedTables {
		if t == table {
			return true
		}
	}
	return false
}

func sqlcQueriesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/storage/tenantguard_test.go → ../../sqlc/queries
	return filepath.Join(filepath.Dir(file), "..", "..", "sqlc", "queries")
}

// splitQueries parses an sqlc-style file into (name, body) pairs separated by
// `-- name:` markers.
func splitQueries(src string) []struct{ name, body string } {
	var out []struct{ name, body string }
	lines := strings.Split(src, "\n")
	var name string
	var buf strings.Builder
	flush := func() {
		body := strings.TrimSpace(buf.String())
		if name != "" && body != "" {
			out = append(out, struct{ name, body string }{name, body})
		}
		name = ""
		buf.Reset()
	}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "-- name:") {
			flush()
			name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "-- name:"))
			if i := strings.Index(name, " "); i > 0 {
				name = name[:i]
			}
			continue
		}
		buf.WriteString(line)
		buf.WriteString("\n")
	}
	flush()
	return out
}
