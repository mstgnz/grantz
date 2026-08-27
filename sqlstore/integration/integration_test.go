//go:build integration

// Package integration exercises sqlstore against a real Postgres, because what these
// tests check is the SQL itself: the union of role grants with user exceptions, the
// active-role filter, and the upsert. A mock would only prove that the strings in this
// file match the strings in the other one.
//
// This is a SEPARATE MODULE, and that is the whole point. The tests need a Postgres
// driver, and a test dependency in the library's own go.mod is not free: Go's minimal
// version selection would push that driver version onto every consumer. A project
// already on lib/pq would find its driver upgraded by importing an authorization
// library. Keeping the driver here means the published grantz module requires nothing.
//
// Run it with a database:
//
//	docker compose up -d
//	GRANTZ_TEST_DSN="postgres://grantz:grantz@localhost:5433/grantz?sslmode=disable" \
//	  go test -tags=integration ./sqlstore/integration/
package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/mstgnz/grantz"
	"github.com/mstgnz/grantz/sqlstore"
)

func testDB(t *testing.T) *sql.DB { return schemaDB(t, "../../migrations/001_init.sql") }

// uuidTestDB is testDB against the uuid variant of the schema.
func uuidTestDB(t *testing.T) *sql.DB { return schemaDB(t, "../../migrations/001_init_uuid.sql") }

func schemaDB(t *testing.T, migration string) *sql.DB {
	t.Helper()

	dsn := os.Getenv("GRANTZ_TEST_DSN")
	if dsn == "" {
		t.Skip("GRANTZ_TEST_DSN not set")
	}

	db, err := sql.Open("postgres", dsn)
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
// The two schema files define the SAME tables with a different user_id type, and
// CREATE TABLE IF NOT EXISTS would quietly keep whichever suite ran first: the uuid tests
// would then insert into a bigint column and fail in a way that reads like a driver bug.
// Dropping makes the file under test the one actually in effect, whatever ran before it.
func applySchema(t *testing.T, db *sql.DB, migration string) {
	t.Helper()

	// Order matters: the child tables reference the parents.
	for _, table := range []string{
		"grantz_user_permissions",
		"grantz_user_roles",
		"grantz_role_permissions",
		"grantz_roles",
		"grantz_permissions",
	} {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + table + " CASCADE"); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}

	schema, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if _, err := db.Exec(string(schema)); err != nil {
		t.Fatalf("apply schema: %v", err)
	}
}

func seed(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

// TestLoadUserGrantsUnionsRolesAndExceptions is the query's whole job: role grants and
// user-level exceptions have to come back together, denials included. Returning only the
// allowances would leave the authorizer unable to honour deny precedence, and the
// symptom would be that revoking one person's access silently does nothing.
func TestLoadUserGrantsUnionsRolesAndExceptions(t *testing.T) {
	db := testDB(t)
	store := sqlstore.New(db)

	seed(t, db,
		`INSERT INTO grantz_permissions (key, resource, action) VALUES
		   ('invoices.create', 'invoices', 'create'),
		   ('invoices.cancel', 'invoices', 'cancel')`,
		`INSERT INTO grantz_roles (id, key, name) VALUES (1, 'clerk', 'Clerk')`,
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

	var sawDeny bool
	for _, g := range grants {
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
}

// TestInactiveRoleIsIgnored: deactivating a role is how access gets suspended, and it has
// to take effect in the query rather than relying on every caller to remember.
func TestInactiveRoleIsIgnored(t *testing.T) {
	db := testDB(t)
	store := sqlstore.New(db)

	seed(t, db,
		`INSERT INTO grantz_permissions (key, resource, action) VALUES ('invoices.create', 'invoices', 'create')`,
		`INSERT INTO grantz_roles (id, key, name, active) VALUES (1, 'suspended', 'Suspended', false)`,
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

// TestFieldsAndScopeRoundTrip through jsonb and back.
func TestFieldsAndScopeRoundTrip(t *testing.T) {
	db := testDB(t)
	store := sqlstore.New(db)

	seed(t, db,
		`INSERT INTO grantz_permissions (key, resource, action, has_fields) VALUES
		   ('invoices.select', 'invoices', 'select', true)`,
		`INSERT INTO grantz_roles (id, key, name) VALUES (1, 'viewer', 'Viewer')`,
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

// TestSyncPermissionsUpsertsAndReportsOrphans.
//
// The orphan half is the important one: a key the code no longer declares is REPORTED,
// never deleted. Deleting would cascade to grantz_role_permissions, so a rollback to an
// older binary would silently wipe an administrator's configuration.
func TestSyncPermissionsUpsertsAndReportsOrphans(t *testing.T) {
	db := testDB(t)
	store := sqlstore.New(db)
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
		`SELECT description FROM grantz_permissions WHERE key = 'invoices.create'`,
	).Scan(&description); err != nil {
		t.Fatalf("read description: %v", err)
	}
	if description != "updated" {
		t.Errorf("description = %q, want updated", description)
	}

	var stillThere int
	if err := db.QueryRow(
		`SELECT count(*) FROM grantz_permissions WHERE key = 'invoices.cancel'`,
	).Scan(&stillThere); err != nil {
		t.Fatalf("count orphan: %v", err)
	}
	if stillThere != 1 {
		t.Error("the orphaned permission was deleted; it must only be reported")
	}
}

// TestUUIDUserIDAgainstTheUUIDSchema is the reason the kit's user id is a type parameter.
//
// It runs the same query as every other test here, against 001_init_uuid.sql, with
// uuid.UUID as the id: the value reaches the driver through driver.Valuer, is matched
// against a uuid column, and the grants resolve exactly as they do for a bigint project.
// Without this, "uuid works" would be a claim in the README rather than a fact.
func TestUUIDUserIDAgainstTheUUIDSchema(t *testing.T) {
	db := uuidTestDB(t)
	store := sqlstore.NewOf[uuid.UUID](db)

	clerk := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	stranger := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	seed(t, db,
		`INSERT INTO grantz_permissions (key, resource, action) VALUES
		   ('invoices.create', 'invoices', 'create'),
		   ('invoices.cancel', 'invoices', 'cancel')`,
		`INSERT INTO grantz_roles (id, key, name) VALUES (1, 'clerk', 'Clerk')`,
		`INSERT INTO grantz_role_permissions (role_id, permission_key) VALUES
		   (1, 'invoices.create'),
		   (1, 'invoices.cancel')`,
	)
	if _, err := db.Exec(`INSERT INTO grantz_user_roles (user_id, role_id) VALUES ($1, 1)`, clerk); err != nil {
		t.Fatalf("seed user role: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO grantz_user_permissions (user_id, permission_key, effect) VALUES ($1, 'invoices.cancel', 'deny')`,
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
