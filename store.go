package grantz

import "context"

// StoreOf is everything the kit needs from a database, and the reason the core package
// imports nothing but the standard library.
//
// A GORM project, an sqlx project and a project on some other driver all satisfy this
// with a thin adapter; sqlstore ships a database/sql implementation that covers the
// first two, since both can hand over a *sql.DB. Swapping Postgres for something else
// is a matter of writing one type, not of forking the kit.
type StoreOf[T comparable] interface {
	// LoadUserGrants returns every grant that applies to a user, from both roles and
	// user-level exceptions. Returning denials as well as allowances is deliberate: the
	// authorizer needs to see a deny to honour its precedence, so filtering here would
	// quietly break it.
	LoadUserGrants(ctx context.Context, userID T) ([]Grant, error)

	// SyncPermissions reconciles the catalogue with the list declared in code:
	// inserts what is new, updates descriptions, and reports keys that exist in the
	// database but no longer in code.
	//
	// It must NOT delete those orphans. A key can disappear from the catalogue because a
	// feature was removed, or because a deploy is running an older binary, and deleting
	// would cascade away the role mappings an administrator configured. Report and let a
	// human decide.
	SyncPermissions(ctx context.Context, perms []Permission) (orphans []string, err error)
}
