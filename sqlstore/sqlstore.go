// Package sqlstore is the database/sql implementation of grantz.Store.
//
// It depends on database/sql and nothing else, so a GORM project hands it db.DB(), an
// sqlx project hands it db.DB, and a project on a raw driver hands it the handle it
// already has. That is the whole reason the kit splits the store out: the core package
// stays on the standard library and every ORM is somebody else's decision.
//
// It ships SQL for Postgres and for MySQL 8.0.19+. The two differ in four mechanical
// places, all of them in dialect.go; everything else, including the fail-closed decoding
// of a malformed field restriction, is the same code on both engines. A third engine
// implements grantz.StoreOf itself, which is a file this size, not a fork of the kit.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/mstgnz/grantz"
)

// StoreOf implements grantz.StoreOf on top of database/sql.
type StoreOf[T comparable] struct {
	db *sql.DB
	// dialect carries the per-engine SQL. It is set by the constructors and never
	// changes: a store is built for one engine and asking it about another is not a
	// runtime decision anyone should be able to make.
	dialect dialect
}

// Store is the int64 instantiation, which is what the bigint user_id column in
// migrations/001_init_postgres.sql expects.
type Store = StoreOf[int64]

// New returns a Postgres Store over the given handle, for int64 user ids.
//
// Postgres is what the unqualified name means, and it stays that way: this function
// existed before the package spoke a second dialect, and a project that upgrades must not
// find its store pointing at another engine. MySQL asks for it by name, below.
func New(db *sql.DB) *Store { return NewOf[int64](db) }

// NewOf returns a Postgres Store for any other user id type, e.g. NewOf[uuid.UUID](db)
// against migrations/001_init_postgres_uuid.sql.
//
// T is handed to the driver as a query argument, so it has to be something database/sql
// accepts: a base type, or a type implementing driver.Valuer. uuid.UUID does.
func NewOf[T comparable](db *sql.DB) *StoreOf[T] {
	return &StoreOf[T]{db: db, dialect: postgresDialect}
}

// NewMySQL returns a MySQL Store over the given handle, for int64 user ids, against
// migrations/001_init_mysql.sql.
//
// It needs MySQL 8.0.19 or later, for the row-alias upsert. See dialect.go for why that
// floor rather than the older form that would also reach 5.7 and MariaDB.
func NewMySQL(db *sql.DB) *Store { return NewMySQLOf[int64](db) }

// NewMySQLOf is NewMySQL for a user id type other than int64, e.g.
// NewMySQLOf[uuid.UUID](db) against migrations/001_init_mysql_uuid.sql, where the column
// is char(36) because uuid.UUID hands the driver its string form.
func NewMySQLOf[T comparable](db *sql.DB) *StoreOf[T] {
	return &StoreOf[T]{db: db, dialect: mysqlDialect}
}

// LoadUserGrants reads every grant that applies to a user in one round trip.
//
// Roles and user-level exceptions come back in a single UNION rather than two queries,
// because the authorizer has to see both before it can honour deny precedence, and two
// queries mean two chances to see an inconsistent picture between them.
//
// Inactive roles are filtered here rather than in the authorizer: deactivating a role is
// how an administrator suspends access, and it has to take effect without every caller
// remembering to check.
func (s *StoreOf[T]) LoadUserGrants(ctx context.Context, userID T) ([]grantz.Grant, error) {
	// The same id fills every placeholder. Postgres reuses $1 and wants it once, MySQL
	// spells both halves of the union with ? and wants it twice; the dialect says which.
	args := make([]any, s.dialect.userIDArgs)
	for i := range args {
		args[i] = userID
	}

	rows, err := s.db.QueryContext(ctx, s.dialect.loadGrants, args...)
	if err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: load grants: %w", err)
	}
	defer rows.Close()

	var grants []grantz.Grant
	for rows.Next() {
		var (
			key      string
			effect   string
			fieldsBs []byte
			scopeBs  []byte
			fromRole bool
		)
		if err := rows.Scan(&key, &effect, &fieldsBs, &scopeBs, &fromRole); err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: scan grant: %w", err)
		}

		fields, err := decodeFields(fieldsBs)
		if err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: permission %q: %w", key, err)
		}
		scope, err := decodeScope(scopeBs)
		if err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: permission %q: %w", key, err)
		}

		grants = append(grants, grantz.Grant{
			Key:      key,
			Effect:   grantz.Effect(effect),
			Fields:   fields,
			Scope:    scope,
			FromRole: fromRole,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: iterate grants: %w", err)
	}
	return grants, nil
}

// SyncPermissions upserts the declared catalogue and reports keys the database still has
// but the code no longer declares.
//
// Orphans are reported, never deleted. Deleting would cascade to grantz_role_permissions
// and silently wipe an administrator's configuration the first time an older binary
// starts up. Removing a permission for real is a migration someone writes on purpose.
func (s *StoreOf[T]) SyncPermissions(ctx context.Context, perms []grantz.Permission) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	declared := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		declared[p.Key] = struct{}{}
		if _, err := tx.ExecContext(ctx, s.dialect.upsertPermission,
			p.Key, p.Resource(), p.Action(), p.Description, p.HasFields,
		); err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: upsert %q: %w", p.Key, err)
		}
	}

	rows, err := tx.QueryContext(ctx, s.dialect.listPermissionKeys)
	if err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: list permissions: %w", err)
	}
	defer rows.Close()

	var orphans []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: scan permission: %w", err)
		}
		if _, ok := declared[key]; !ok {
			orphans = append(orphans, key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: iterate permissions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: close rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: commit: %w", err)
	}
	return orphans, nil
}

// decodeFields reads the {"allow": [...]} shape.
//
// A NULL column means unrestricted and comes back as a nil slice. An unparseable value is
// an error rather than a silent "unrestricted": a malformed restriction that reads as no
// restriction is the failure mode that gets data exposed.
func decodeFields(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var payload struct {
		Allow []string `json:"allow"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("invalid fields json: %w", err)
	}
	return payload.Allow, nil
}

func decodeScope(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var scope map[string]any
	if err := json.Unmarshal(raw, &scope); err != nil {
		return nil, fmt.Errorf("invalid scope json: %w", err)
	}
	return scope, nil
}
