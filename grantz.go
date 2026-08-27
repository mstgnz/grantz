// Package grantz is a permission kit for Go services.
//
// The unit of authorization is a business verb, not a table: "invoices.cancel",
// "users.create". Roles hold verbs, users hold roles, and a per-user exception can add
// or remove a single verb without cloning a role. Field-level restrictions are optional
// and off unless a grant defines them.
//
// What the kit deliberately does not do:
//
//   - It does not own users. You pass a user id; where users live is your business.
//   - It does not decide whether a record belongs to a user. It hands back the scope a
//     role was granted with and lets the caller compare, because that comparison is
//     domain knowledge and putting it here turns a permission kit into an ORM.
//   - It does not talk to a specific database. Everything goes through Store.
//
// Fail-closed everywhere: no grant means denied, and an error resolving grants means
// denied rather than allowed.
package grantz

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrDenied is returned by Require when the user lacks the permission. Callers map it to
// whatever their transport calls a 403; the kit does not import net/http for this.
var ErrDenied = errors.New("grantz: permission denied")

// ErrNoUser is returned when the context carries no user. It is distinct from ErrDenied
// so an unauthenticated request can be answered with 401 rather than 403.
var ErrNoUser = errors.New("grantz: no user in context")

// UserIDFunc extracts the current user id from a context.
//
// The kit cannot know how a host application stores its user: a struct under a context
// key, a JWT claim, a request-scoped session. You supply the one line that reads it.
type UserIDFunc func(ctx context.Context) (int64, bool)

// Config wires an Authorizer.
type Config struct {
	// Store is required.
	Store Store

	// UserID is required for the context-based helpers (CanCtx, RequireCtx, Middleware).
	// The explicit forms that take a user id work without it.
	UserID UserIDFunc

	// Cache is optional. When nil, CacheTTL decides: a positive TTL builds an in-process
	// cache, zero disables caching entirely.
	Cache    Cache
	CacheTTL time.Duration

	// Superuser is optional. When it returns true the user is allowed everything without
	// consulting the store.
	//
	// Every real system ends up needing this, and the ones that pretend otherwise grow a
	// role called "admin" that is granted every permission and forgotten at the next
	// release. Making it an explicit hook keeps the bypass visible and greppable.
	Superuser func(ctx context.Context, userID int64) bool
}

// Authorizer answers permission questions.
type Authorizer struct {
	store     Store
	cache     Cache
	userID    UserIDFunc
	superuser func(ctx context.Context, userID int64) bool
}

// New builds an Authorizer. It returns an error rather than panicking so a misconfigured
// service fails at startup with a readable message.
func New(cfg Config) (*Authorizer, error) {
	if cfg.Store == nil {
		return nil, errors.New("grantz: Store is required")
	}

	cache := cfg.Cache
	if cache == nil {
		if cfg.CacheTTL > 0 {
			cache = NewMemoryCache(cfg.CacheTTL)
		} else {
			cache = noopCache{}
		}
	}

	return &Authorizer{
		store:     cfg.Store,
		cache:     cache,
		userID:    cfg.UserID,
		superuser: cfg.Superuser,
	}, nil
}

// Sync reconciles the permission catalogue with what the code declares.
//
// Call it once at startup, after migrations. Keys that exist in the database but not in
// the list are reported, never deleted: an older binary rolling back would otherwise
// cascade away the role mappings an administrator configured.
func (a *Authorizer) Sync(ctx context.Context, perms []Permission) (orphans []string, err error) {
	seen := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if _, dup := seen[p.Key]; dup {
			return nil, fmt.Errorf("grantz: permission %q declared twice", p.Key)
		}
		seen[p.Key] = struct{}{}
	}
	return a.store.SyncPermissions(ctx, perms)
}

// Decide resolves one permission for one user.
//
// Prefer Can or Require unless you need the field list or the scopes.
func (a *Authorizer) Decide(ctx context.Context, userID int64, key string) (Decision, error) {
	if _, _, err := splitKey(key); err != nil {
		return Decision{}, err
	}

	if a.superuser != nil && a.superuser(ctx, userID) {
		return Decision{Allowed: true}, nil
	}

	grants, err := a.grantsFor(ctx, userID)
	if err != nil {
		return Decision{}, err
	}

	matching := make([]Grant, 0, 4)
	for _, g := range grants {
		if g.Key == key {
			matching = append(matching, g)
		}
	}
	return fold(matching), nil
}

// Can reports whether the user holds the permission.
//
// An error means the answer is unknown, and unknown is treated as denied by every caller
// in this package. Do not turn an error into an allow.
func (a *Authorizer) Can(ctx context.Context, userID int64, key string) (bool, error) {
	decision, err := a.Decide(ctx, userID, key)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// Require returns ErrDenied when the user lacks the permission, nil when they hold it.
func (a *Authorizer) Require(ctx context.Context, userID int64, key string) error {
	allowed, err := a.Can(ctx, userID, key)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: %s", ErrDenied, key)
	}
	return nil
}

// Fields returns the field allow-list for a permission the user holds.
//
// A nil list means every field is allowed, which is not the same as an empty list; an
// empty non-nil list would mean "allowed to act, on nothing". Callers that restrict a
// SELECT should treat nil as "no restriction" and not as "no columns".
//
// Returns ErrDenied when the user does not hold the permission at all, so a caller
// cannot mistake a denial for an unrestricted result.
func (a *Authorizer) Fields(ctx context.Context, userID int64, key string) ([]string, error) {
	decision, err := a.Decide(ctx, userID, key)
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrDenied, key)
	}
	return decision.Fields, nil
}

// Scopes returns the scopes attached to the roles that granted this permission.
//
// Nil means the permission was granted without a scope, i.e. unrestricted. More than one
// entry means several roles granted it with different scopes; the caller decides how to
// combine them, because whether two scopes union or intersect depends on what they mean.
func (a *Authorizer) Scopes(ctx context.Context, userID int64, key string) ([]map[string]any, error) {
	decision, err := a.Decide(ctx, userID, key)
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return nil, fmt.Errorf("%w: %s", ErrDenied, key)
	}
	return decision.Scopes, nil
}

// UserPermissions returns every permission key the user holds, sorted.
//
// This is what a UI asks for once after login so it can decide which screens and buttons
// to draw. Handing the client a list rather than making it ask per screen keeps the
// navigation logic on the client where it belongs, while the answer still comes from the
// same rows the server enforces with. A menu that is hidden because the key is missing
// and an endpoint that refuses for the same reason cannot drift apart.
//
// It is a convenience over the same grants, not a second source of truth: never let a
// client decide anything with this list that the server does not check again.
func (a *Authorizer) UserPermissions(ctx context.Context, userID int64) ([]string, error) {
	grants, err := a.grantsFor(ctx, userID)
	if err != nil {
		return nil, err
	}

	byKey := make(map[string][]Grant)
	for _, g := range grants {
		byKey[g.Key] = append(byKey[g.Key], g)
	}

	keys := make([]string, 0, len(byKey))
	for key, keyGrants := range byKey {
		if fold(keyGrants).Allowed {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

// UserPermissionsCtx is UserPermissions for the user in the context.
func (a *Authorizer) UserPermissionsCtx(ctx context.Context) ([]string, error) {
	userID, err := a.userIDFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	return a.UserPermissions(ctx, userID)
}

// CanCtx is Can for the user in the context. Requires Config.UserID.
func (a *Authorizer) CanCtx(ctx context.Context, key string) (bool, error) {
	userID, err := a.userIDFromCtx(ctx)
	if err != nil {
		return false, err
	}
	return a.Can(ctx, userID, key)
}

// RequireCtx is Require for the user in the context. Requires Config.UserID.
func (a *Authorizer) RequireCtx(ctx context.Context, key string) error {
	userID, err := a.userIDFromCtx(ctx)
	if err != nil {
		return err
	}
	return a.Require(ctx, userID, key)
}

// Invalidate drops a user's cached grants. Call it after changing their roles or
// exceptions, otherwise the change waits for the TTL.
func (a *Authorizer) Invalidate(ctx context.Context, userID int64) {
	a.cache.Invalidate(ctx, userID)
}

// InvalidateAll drops every cached grant. Call it after editing a role, since that
// affects every user holding it and the kit does not track who those are.
func (a *Authorizer) InvalidateAll(ctx context.Context) {
	a.cache.InvalidateAll(ctx)
}

func (a *Authorizer) grantsFor(ctx context.Context, userID int64) ([]Grant, error) {
	if grants, ok := a.cache.Get(ctx, userID); ok {
		return grants, nil
	}
	grants, err := a.store.LoadUserGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	a.cache.Set(ctx, userID, grants)
	return grants, nil
}

func (a *Authorizer) userIDFromCtx(ctx context.Context) (int64, error) {
	if a.userID == nil {
		return 0, errors.New("grantz: Config.UserID is required for context-based checks")
	}
	userID, ok := a.userID(ctx)
	if !ok {
		return 0, ErrNoUser
	}
	return userID, nil
}
