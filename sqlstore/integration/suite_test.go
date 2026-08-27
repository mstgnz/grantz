//go:build integration

// Package integration exercises sqlstore against real databases, because what these tests
// check is the SQL itself: the union of role grants with user exceptions, the active-role
// filter, and the upsert. A mock would only prove that the strings in this file match the
// strings in the other one.
//
// The suite is written once and run against every engine the store speaks. That is the
// point of the engine table below: a behaviour that holds on Postgres and not on MySQL is
// exactly the kind of difference a second dialect introduces, and it has to fail here
// rather than in whichever project happens to be on the other engine.
//
// This is a SEPARATE MODULE, and that is deliberate. The tests need database drivers, and
// a test dependency in the library's own go.mod is not free: Go's minimal version
// selection would push those driver versions onto every consumer. A project already on
// lib/pq would find its driver upgraded by importing an authorization library. Keeping
// the drivers here means the published grantz module requires nothing.
//
// Run it with databases:
//
//	docker compose up -d
//	GRANTZ_TEST_DSN="postgres://grantz:grantz@localhost:5433/grantz?sslmode=disable" \
//	GRANTZ_TEST_MYSQL_DSN="grantz:grantz@tcp(localhost:3307)/grantz" \
//	  go test -tags=integration ./sqlstore/integration/
//
// Each engine skips when its own DSN is unset, so running one of them is fine.
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/mstgnz/grantz"
	"github.com/mstgnz/grantz/sqlstore"
)

// engine is everything the suite needs to know about a database it is running against.
//
// The list is short on purpose: if it grew to hold per-engine assertions, the suite would
// have stopped testing that the two behave the same.
type engine struct {
	name       string
	driver     string
	dsnEnv     string
	schema     string
	uuidSchema string

	// keyColumn is the only identifier the seeds have to spell differently. KEY is
	// reserved in MySQL and needs backticks; Postgres takes it bare and would reject the
	// backticks. There is no spelling both accept.
	keyColumn string

	// placeholder is how the nth bind parameter is written, for the seeds that take one.
	placeholder func(n int) string

	newStore     func(*sql.DB) *sqlstore.Store
	newUUIDStore func(*sql.DB) *sqlstore.StoreOf[uuid.UUID]
}

var postgres = engine{
	name:         "postgres",
	driver:       "postgres",
	dsnEnv:       "GRANTZ_TEST_DSN",
	schema:       "../../migrations/001_init_postgres.sql",
	uuidSchema:   "../../migrations/001_init_postgres_uuid.sql",
	keyColumn:    "key",
	placeholder:  func(n int) string { return fmt.Sprintf("$%d", n) },
	newStore:     sqlstore.New,
	newUUIDStore: sqlstore.NewOf[uuid.UUID],
}

var mysql = engine{
	name:         "mysql",
	driver:       "mysql",
	dsnEnv:       "GRANTZ_TEST_MYSQL_DSN",
	schema:       "../../migrations/001_init_mysql.sql",
	uuidSchema:   "../../migrations/001_init_mysql_uuid.sql",
	keyColumn:    "`key`",
	placeholder:  func(int) string { return "?" },
	newStore:     sqlstore.NewMySQL,
	newUUIDStore: sqlstore.NewMySQLOf[uuid.UUID],
}

// runSuite is the whole contract, run against one engine.
func runSuite(t *testing.T, e engine) {
	t.Run("LoadUserGrantsUnionsRolesAndExceptions", func(t *testing.T) { testUnionsRolesAndExceptions(t, e) })
	t.Run("InactiveRoleIsIgnored", func(t *testing.T) { testInactiveRoleIsIgnored(t, e) })
	t.Run("FieldsAndScopeRoundTrip", func(t *testing.T) { testFieldsAndScopeRoundTrip(t, e) })
	t.Run("SyncPermissionsUpsertsAndReportsOrphans", func(t *testing.T) { testSyncUpsertsAndReportsOrphans(t, e) })
	t.Run("UUIDUserIDAgainstTheUUIDSchema", func(t *testing.T) { testUUIDUserID(t, e) })
}

func testDB(t *testing.T, e engine) *sql.DB { return schemaDB(t, e, e.schema) }

// uuidTestDB is testDB against the uuid variant of the schema.
func uuidTestDB(t *testing.T, e engine) *sql.DB { return schemaDB(t, e, e.uuidSchema) }

func schemaDB(t *testing.T, e engine, migration string) *sql.DB {
	t.Helper()

	dsn := os.Getenv(e.dsnEnv)
	if dsn == "" {
		t.Skipf("%s not set", e.dsnEnv)
	}

	db, err := sql.Open(e.driver, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	applySchema(t, db, migration)
	return db
}

// applySchema drops the tables before creating them, rather than truncating.
//
// The schema files define the SAME tables with a different user_id type, and
// CREATE TABLE IF NOT EXISTS would quietly keep whichever suite ran first: the uuid tests
// would then insert into a bigint column and fail in a way that reads like a driver bug.
// Dropping makes the file under test the one actually in effect, whatever ran before it.
func applySchema(t *testing.T, db *sql.DB, migration string) {
	t.Helper()

	// Order matters: the child tables reference the parents. Dropping child-first also
	// avoids CASCADE, which Postgres accepts and MySQL does not.
	for _, table := range []string{
		"grantz_user_permissions",
		"grantz_user_roles",
		"grantz_role_permissions",
		"grantz_roles",
		"grantz_permissions",
	} {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}

	for _, stmt := range statements(t, migration) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("apply schema %s: %v\n%s", migration, err, stmt)
		}
	}
}

// statements splits a migration into single statements.
//
// One Exec per statement rather than handing the whole file over: the MySQL driver refuses
// multiple statements in one call unless the DSN opts in, and a DSN flag is a worse thing
// to require of whoever runs these than a split on semicolons. The schema files carry no
// semicolon inside a string or a body, which is what makes the naive split safe.
func statements(t *testing.T, path string) []string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}

	var stripped strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		stripped.WriteString(line)
		stripped.WriteString("\n")
	}

	var out []string
	for _, stmt := range strings.Split(stripped.String(), ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		out = append(out, stmt)
	}
	return out
}

func seed(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

// testUnionsRolesAndExceptions is the query's whole job: role grants and user-level
// exceptions have to come back together, denials included. Returning only the allowances
// would leave the authorizer unable to honour deny precedence, and the symptom would be
// that revoking one person's access silently does nothing.
func testUnionsRolesAndExceptions(t *testing.T, e engine) {
	db := testDB(t, e)
	store := e.newStore(db)

	seed(t, db,
		fmt.Sprintf(`INSERT INTO grantz_permissions (%s, resource, action) VALUES
		   ('invoices.create', 'invoices', 'create'),
		   ('invoices.cancel', 'invoices', 'cancel')`, e.keyColumn),
		fmt.Sprintf(`INSERT INTO grantz_roles (id, %s, name) VALUES (1, 'clerk', 'Clerk')`, e.keyColumn),
		`INSERT INTO grantz_role_permissions (role_id, permission_key) VALUES
		   (1, 'invoices.create'),
		   (1, 'invoices.cancel')`,
		`INSERT INTO grantz_user_roles (user_id, role_id) VALUES (7, 1)`,
		`INSERT INTO grantz_user_permissions (user_id, permission_key, effect) VALUES
		   (7, 'invoices.cancel', 'deny')`,
	)

	grants, err := store.LoadUserGrants(context.Background(), 7)
	if err != nil {
		t.Fatalf("LoadUserGrants: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("got %d grants, want 3 (2 from the role, 1 exception)", len(grants))
	}

	var sawDeny, sawRoleGrant bool
	for _, g := range grants {
		if g.Key == "invoices.create" && g.FromRole {
			sawRoleGrant = true
		}
		if g.Key == "invoices.cancel" && g.Effect == grantz.EffectDeny {
			sawDeny = true
			if g.FromRole {
				t.Error("the exception was reported as coming from a role")
			}
		}
	}
	if !sawDeny {
		t.Fatal("the user-level deny did not come back")
	}
	// from_role is a boolean literal in the query, and MySQL returns it as 1 and 0 rather
	// than as a boolean. If that ever stopped converting, every grant would look like an
	// exception and deny precedence would still work, so nothing else here would notice.
	if !sawRoleGrant {
		t.Error("no grant came back marked as coming from a role")
	}
}

// testInactiveRoleIsIgnored: deactivating a role is how access gets suspended, and it has
// to take effect in the query rather than relying on every caller to remember.
func testInactiveRoleIsIgnored(t *testing.T, e engine) {
	db := testDB(t, e)
	store := e.newStore(db)

	seed(t, db,
		fmt.Sprintf(`INSERT INTO grantz_permissions (%s, resource, action) VALUES ('invoices.create', 'invoices', 'create')`, e.keyColumn),
		fmt.Sprintf(`INSERT INTO grantz_roles (id, %s, name, active) VALUES (1, 'suspended', 'Suspended', false)`, e.keyColumn),
		`INSERT INTO grantz_role_permissions (role_id, permission_key) VALUES (1, 'invoices.create')`,
		`INSERT INTO grantz_user_roles (user_id, role_id) VALUES (7, 1)`,
	)

	grants, err := store.LoadUserGrants(context.Background(), 7)
	if err != nil {
		t.Fatalf("LoadUserGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("got %d grants from an inactive role, want 0", len(grants))
	}
}

// testFieldsAndScopeRoundTrip through the json columns and back.
func testFieldsAndScopeRoundTrip(t *testing.T, e engine) {
	db := testDB(t, e)
	store := e.newStore(db)

	seed(t, db,
		fmt.Sprintf(`INSERT INTO grantz_permissions (%s, resource, action, has_fields) VALUES
		   ('invoices.select', 'invoices', 'select', true)`, e.keyColumn),
		fmt.Sprintf(`INSERT INTO grantz_roles (id, %s, name) VALUES (1, 'viewer', 'Viewer')`, e.keyColumn),
		`INSERT INTO grantz_role_permissions (role_id, permission_key, fields) VALUES
		   (1, 'invoices.select', '{"allow":["id","total"]}')`,
		`INSERT INTO grantz_user_roles (user_id, role_id, scope) VALUES
		   (7, 1, '{"company_id":12}')`,
	)

	grants, err := store.LoadUserGrants(context.Background(), 7)
	if err != nil {
		t.Fatalf("LoadUserGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("got %d grants, want 1", len(grants))
	}

	g := grants[0]
	if len(g.Fields) != 2 || g.Fields[0] != "id" || g.Fields[1] != "total" {
		t.Errorf("fields = %v, want [id total]", g.Fields)
	}
	if g.Scope["company_id"] != float64(12) {
		t.Errorf("scope = %v, want company_id 12", g.Scope)
	}
}

// testSyncUpsertsAndReportsOrphans.
//
// The orphan half is the important one: a key the code no longer declares is REPORTED,
// never deleted. Deleting would cascade to grantz_role_permissions, so a rollback to an
// older binary would silently wipe an administrator's configuration.
func testSyncUpsertsAndReportsOrphans(t *testing.T, e engine) {
	db := testDB(t, e)
	store := e.newStore(db)
	ctx := context.Background()

	if _, err := store.SyncPermissions(ctx, []grantz.Permission{
		{Key: "invoices.create", Description: "first"},
		{Key: "invoices.cancel", Description: "cancel"},
	}); err != nil {
		t.Fatalf("first sync: %v", err)
	}

	// Second run drops one key from the declaration and changes a description.
	orphans, err := store.SyncPermissions(ctx, []grantz.Permission{
		{Key: "invoices.create", Description: "updated"},
	})
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if len(orphans) != 1 || orphans[0] != "invoices.cancel" {
		t.Fatalf("orphans = %v, want [invoices.cancel]", orphans)
	}

	var description string
	if err := db.QueryRow(
		fmt.Sprintf(`SELECT description FROM grantz_permissions WHERE %s = 'invoices.create'`, e.keyColumn),
	).Scan(&description); err != nil {
		t.Fatalf("read description: %v", err)
	}
	if description != "updated" {
		t.Errorf("description = %q, want updated", description)
	}

	var stillThere int
	if err := db.QueryRow(
		fmt.Sprintf(`SELECT count(*) FROM grantz_permissions WHERE %s = 'invoices.cancel'`, e.keyColumn),
	).Scan(&stillThere); err != nil {
		t.Fatalf("count orphan: %v", err)
	}
	if stillThere != 1 {
		t.Error("the orphaned permission was deleted; it must only be reported")
	}
}

// testUUIDUserID is the reason the kit's user id is a type parameter.
//
// It runs the same query as every other test here, against the uuid schema, with
// uuid.UUID as the id: the value reaches the driver through driver.Valuer, is matched
// against a uuid column on Postgres and a char(36) one on MySQL, and the grants resolve
// exactly as they do for a bigint project. Without this, "uuid works" would be a claim in
// the README rather than a fact.
func testUUIDUserID(t *testing.T, e engine) {
	db := uuidTestDB(t, e)
	store := e.newUUIDStore(db)

	clerk := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	stranger := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	seed(t, db,
		fmt.Sprintf(`INSERT INTO grantz_permissions (%s, resource, action) VALUES
		   ('invoices.create', 'invoices', 'create'),
		   ('invoices.cancel', 'invoices', 'cancel')`, e.keyColumn),
		fmt.Sprintf(`INSERT INTO grantz_roles (id, %s, name) VALUES (1, 'clerk', 'Clerk')`, e.keyColumn),
		`INSERT INTO grantz_role_permissions (role_id, permission_key) VALUES
		   (1, 'invoices.create'),
		   (1, 'invoices.cancel')`,
	)
	if _, err := db.Exec(
		fmt.Sprintf(`INSERT INTO grantz_user_roles (user_id, role_id) VALUES (%s, 1)`, e.placeholder(1)),
		clerk,
	); err != nil {
		t.Fatalf("seed user role: %v", err)
	}
	if _, err := db.Exec(
		fmt.Sprintf(`INSERT INTO grantz_user_permissions (user_id, permission_key, effect) VALUES (%s, 'invoices.cancel', 'deny')`, e.placeholder(1)),
		clerk,
	); err != nil {
		t.Fatalf("seed exception: %v", err)
	}

	grants, err := store.LoadUserGrants(context.Background(), clerk)
	if err != nil {
		t.Fatalf("LoadUserGrants: %v", err)
	}
	if len(grants) != 3 {
		t.Fatalf("got %d grants, want 3 (2 from the role, 1 exception)", len(grants))
	}

	// And the whole way through the authorizer, so the deny still wins for a uuid user.
	authz, err := grantz.NewOf(grantz.ConfigOf[uuid.UUID]{Store: store})
	if err != nil {
		t.Fatalf("NewOf: %v", err)
	}
	ctx := context.Background()
	if allowed, err := authz.Can(ctx, clerk, "invoices.create"); err != nil || !allowed {
		t.Fatalf("invoices.create: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := authz.Can(ctx, clerk, "invoices.cancel"); err != nil || allowed {
		t.Fatalf("the user-level deny did not win: allowed=%v err=%v", allowed, err)
	}
	if allowed, err := authz.Can(ctx, stranger, "invoices.create"); err != nil || allowed {
		t.Fatalf("an unrelated uuid was allowed: allowed=%v err=%v", allowed, err)
	}
}
