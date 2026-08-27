// Package sqlstore is the database/sql implementation of grantz.Store.
//
// It depends on database/sql and nothing else, so a GORM project hands it db.DB(), an
// sqlx project hands it db.DB, and a project on a raw driver hands it the handle it
// already has. That is the whole reason the kit splits the store out: the core package
// stays on the standard library and every ORM is somebody else's decision.
//
// The SQL is Postgres (jsonb, $1 placeholders). Another engine needs its own Store,
// which is a file this size, not a fork of the kit.
package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/mstgnz/grantz"
)

// Store implements grantz.Store on top of database/sql.
type Store struct {
	db *sql.DB
}

// New returns a Store over the given handle.
func New(db *sql.DB) *Store {
	return &Store{db: db}
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
func (s *Store) LoadUserGrants(ctx context.Context, userID int64) ([]grantz.Grant, error) {
	const query = `
SELECT rp.permission_key,
       'allow'   AS effect,
       rp.fields,
       ur.scope,
       true      AS from_role
  FROM grantz_user_roles ur
  JOIN grantz_roles r            ON r.id = ur.role_id AND r.active
  JOIN grantz_role_permissions rp ON rp.role_id = r.id
 WHERE ur.user_id = $1

UNION ALL

SELECT up.permission_key,
       up.effect,
       up.fields,
       NULL::jsonb AS scope,
       false       AS from_role
  FROM grantz_user_permissions up
 WHERE up.user_id = $1`

	rows, err := s.db.QueryContext(ctx, query, userID)
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
func (s *Store) SyncPermissions(ctx context.Context, perms []grantz.Permission) ([]string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("grantz/sqlstore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	const upsert = `
INSERT INTO grantz_permissions (key, resource, action, description, has_fields)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (key) DO UPDATE
   SET resource    = EXCLUDED.resource,
       action      = EXCLUDED.action,
       description = EXCLUDED.description,
       has_fields  = EXCLUDED.has_fields`

	declared := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		declared[p.Key] = struct{}{}
		if _, err := tx.ExecContext(ctx, upsert,
			p.Key, p.Resource(), p.Action(), p.Description, p.HasFields,
		); err != nil {
			return nil, fmt.Errorf("grantz/sqlstore: upsert %q: %w", p.Key, err)
		}
	}

	rows, err := tx.QueryContext(ctx, `SELECT key FROM grantz_permissions`)
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
