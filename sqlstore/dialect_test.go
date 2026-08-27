package sqlstore

import (
	"fmt"
	"strings"
	"testing"
)

// allDialects is every engine this package speaks. A new one added to the list without a
// matching entry here is the drift these tests exist to stop.
var allDialects = []dialect{postgresDialect, mysqlDialect}

// TestEachDialectSelectsTheSameFiveColumnsInOrder pins the one thing that cannot be
// checked by the compiler and does not fail loudly at runtime either.
//
// LoadUserGrants scans positionally: key, effect, fields, scope, from_role. A dialect that
// selects scope before fields still returns five columns of the right types, so the query
// succeeds and every grant comes back with its field restriction read as a scope. The
// symptom is a permission that silently loses its restriction, which is the direction that
// exposes data.
func TestEachDialectSelectsTheSameFiveColumnsInOrder(t *testing.T) {
	order := []string{"permission_key", "AS effect", ".fields", ".scope", "AS from_role"}

	for _, d := range allDialects {
		t.Run(d.name, func(t *testing.T) {
			previous := -1
			for _, marker := range order {
				at := strings.Index(d.loadGrants, marker)
				if at < 0 {
					t.Fatalf("loadGrants never selects %q", marker)
				}
				if at < previous {
					t.Fatalf("%q is selected out of order; LoadUserGrants scans by position", marker)
				}
				previous = at
			}
		})
	}
}

// TestPlaceholdersMatchTheArgumentCount.
//
// Postgres numbers its placeholders and reuses $1 for both halves of the union; MySQL has
// no numbering, so the same id is bound twice. Getting userIDArgs wrong is caught by the
// driver at the first query, but only in a project that actually runs that engine, which
// may be someone else's project and not this repository's CI.
func TestPlaceholdersMatchTheArgumentCount(t *testing.T) {
	if got := strings.Count(postgresDialect.loadGrants, "$1"); got != 2 || postgresDialect.userIDArgs != 1 {
		t.Errorf("postgres: %d occurrences of $1 with userIDArgs %d; want 2 and 1",
			got, postgresDialect.userIDArgs)
	}
	if strings.Contains(postgresDialect.loadGrants, "?") {
		t.Error("postgres: a ? placeholder leaked into the numbered dialect")
	}

	if got := strings.Count(mysqlDialect.loadGrants, "?"); got != mysqlDialect.userIDArgs {
		t.Errorf("mysql: %d placeholders but userIDArgs is %d; the driver would refuse the query",
			got, mysqlDialect.userIDArgs)
	}
	if strings.Contains(mysqlDialect.loadGrants, "$") {
		t.Error("mysql: a numbered placeholder leaked into the ? dialect")
	}
}

// TestUpsertBindsEveryCatalogueColumn: SyncPermissions passes five values, so a dialect
// with four placeholders fails on the first startup after a deploy.
func TestUpsertBindsEveryCatalogueColumn(t *testing.T) {
	for i := 1; i <= 5; i++ {
		if !strings.Contains(postgresDialect.upsertPermission, fmt.Sprintf("$%d", i)) {
			t.Errorf("postgres upsert has no $%d", i)
		}
	}
	if got := strings.Count(mysqlDialect.upsertPermission, "?"); got != 5 {
		t.Errorf("mysql upsert has %d placeholders, want 5", got)
	}
}

// TestMySQLQuotesTheReservedKeyColumn.
//
// KEY is reserved in MySQL, so an unquoted key column is a syntax error rather than a
// wrong answer. It is pinned anyway because the natural way to add a statement is to copy
// the Postgres one, where no quoting is needed.
func TestMySQLQuotesTheReservedKeyColumn(t *testing.T) {
	for name, stmt := range map[string]string{
		"upsertPermission":   mysqlDialect.upsertPermission,
		"listPermissionKeys": mysqlDialect.listPermissionKeys,
	} {
		if !strings.Contains(stmt, "`key`") {
			t.Errorf("mysql %s does not quote the key column: %s", name, stmt)
		}
		if strings.Contains(stmt, " key ") || strings.Contains(stmt, "(key,") {
			t.Errorf("mysql %s references key unquoted: %s", name, stmt)
		}
	}
}

// TestEveryDialectReadsTheSameTables. The schema files are shared, and a store that
// queried a table one of them does not define would only fail for that engine's users.
func TestEveryDialectReadsTheSameTables(t *testing.T) {
	tables := []string{
		"grantz_user_roles",
		"grantz_roles",
		"grantz_role_permissions",
		"grantz_user_permissions",
		"grantz_permissions",
	}

	for _, d := range allDialects {
		t.Run(d.name, func(t *testing.T) {
			all := d.loadGrants + d.upsertPermission + d.listPermissionKeys
			for _, table := range tables {
				if !strings.Contains(all, table) {
					t.Errorf("no statement touches %s", table)
				}
			}
			if !strings.Contains(d.loadGrants, "r.active") {
				t.Error("the inactive-role filter is missing; deactivating a role would stop suspending access")
			}
		})
	}
}

// TestConstructorsPickTheirDialect: the unqualified names stay Postgres.
//
// This is a compatibility promise, not a default. A project that upgrades grantz must not
// find New(db) pointing at another engine, and the failure would not be a compile error.
func TestConstructorsPickTheirDialect(t *testing.T) {
	if got := New(nil).dialect.name; got != "postgres" {
		t.Errorf("New is on %s; the unqualified constructor must stay Postgres", got)
	}
	if got := NewOf[string](nil).dialect.name; got != "postgres" {
		t.Errorf("NewOf is on %s; the unqualified constructor must stay Postgres", got)
	}
	if got := NewMySQL(nil).dialect.name; got != "mysql" {
		t.Errorf("NewMySQL is on %s", got)
	}
	if got := NewMySQLOf[string](nil).dialect.name; got != "mysql" {
		t.Errorf("NewMySQLOf is on %s", got)
	}
}
