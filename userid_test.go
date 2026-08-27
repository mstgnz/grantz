package grantz

import (
	"context"
	"testing"
	"time"
)

// uuidLike is the shape a uuid has in Go: [16]byte, which is comparable and therefore a
// valid cache key. Declaring it here rather than importing google/uuid keeps the module
// dependency-free while still exercising the exact case that made the kit generic.
type uuidLike [16]byte

var (
	alice = uuidLike{0xa1}
	bob   = uuidLike{0xb0}
)

type uuidStore struct {
	grants map[uuidLike][]Grant
	calls  int
}

func (s *uuidStore) LoadUserGrants(_ context.Context, userID uuidLike) ([]Grant, error) {
	s.calls++
	return s.grants[userID], nil
}

func (s *uuidStore) SyncPermissions(context.Context, []Permission) ([]string, error) {
	return nil, nil
}

type uuidCtxKey struct{}

// TestUUIDUserIDResolvesLikeInt64 walks the whole path with a non-int64 id: the store,
// the cache keyed on it, the context helper and deny precedence. A uuid project gets the
// same decisions as a bigint one, which is the entire promise of the type parameter.
func TestUUIDUserIDResolvesLikeInt64(t *testing.T) {
	store := &uuidStore{grants: map[uuidLike][]Grant{
		alice: {
			{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true},
			{Key: "invoices.select", Effect: EffectAllow, FromRole: true},
			{Key: "invoices.select", Effect: EffectDeny},
		},
	}}

	a, err := NewOf(ConfigOf[uuidLike]{
		Store:    store,
		CacheTTL: time.Minute,
		UserID: func(ctx context.Context) (uuidLike, bool) {
			id, ok := ctx.Value(uuidCtxKey{}).(uuidLike)
			return id, ok
		},
	})
	if err != nil {
		t.Fatalf("NewOf: %v", err)
	}

	ctx := context.Background()

	allowed, err := a.Can(ctx, alice, "invoices.cancel")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !allowed {
		t.Fatal("role grant did not reach a uuid user")
	}

	// Deny precedence is not a property of the id type, and this proves the fold is
	// reached identically.
	if allowed, err := a.Can(ctx, alice, "invoices.select"); err != nil || allowed {
		t.Fatalf("deny did not win for a uuid user: allowed=%v err=%v", allowed, err)
	}

	// A different uuid is a different cache key and a different answer.
	if allowed, err := a.Can(ctx, bob, "invoices.cancel"); err != nil || allowed {
		t.Fatalf("bob was allowed alice's permission: allowed=%v err=%v", allowed, err)
	}

	// Two loads so far, one per user; the third call for alice must come from the cache.
	if store.calls != 2 {
		t.Fatalf("store called %d times, want 2", store.calls)
	}
	if _, err := a.Can(ctx, alice, "invoices.cancel"); err != nil {
		t.Fatalf("Can: %v", err)
	}
	if store.calls != 2 {
		t.Fatalf("cache missed on a uuid key: store called %d times", store.calls)
	}

	// The context helper carries the same type through.
	if err := a.RequireCtx(context.WithValue(ctx, uuidCtxKey{}, alice), "invoices.cancel"); err != nil {
		t.Fatalf("RequireCtx: %v", err)
	}
	if err := a.RequireCtx(ctx, "invoices.cancel"); err != ErrNoUser {
		t.Fatalf("missing user: got %v, want ErrNoUser", err)
	}
}

// TestStringUserIDCompiles pins that the constraint is not secretly numeric. A project
// keying users on a string id (an external subject, a tenant slug) is a supported case.
func TestStringUserIDCompiles(t *testing.T) {
	a, err := NewOf(ConfigOf[string]{Store: stringStore{}})
	if err != nil {
		t.Fatalf("NewOf: %v", err)
	}
	allowed, err := a.Can(context.Background(), "auth0|42", "invoices.cancel")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if !allowed {
		t.Fatal("string user id did not resolve")
	}
}

type stringStore struct{}

func (stringStore) LoadUserGrants(_ context.Context, userID string) ([]Grant, error) {
	if userID != "auth0|42" {
		return nil, nil
	}
	return []Grant{{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true}}, nil
}

func (stringStore) SyncPermissions(context.Context, []Permission) ([]string, error) {
	return nil, nil
}

// TestInt64APIIsTheAliasNotAFork is the compatibility promise, checked by the compiler:
// the names a pre-generics project uses must BE the int64 instantiation, so its code
// keeps compiling untouched. If someone ever turns one of these into a wrapper type,
// this stops building.
func TestInt64APIIsTheAliasNotAFork(t *testing.T) {
	var (
		_ *Authorizer = (*AuthorizerOf[int64])(nil)
		_ Config      = ConfigOf[int64]{}
		_ Store       = StoreOf[int64](nil)
		_ Cache       = CacheOf[int64](nil)
		_ UserIDFunc  = UserIDFuncOf[int64](nil)
	)
}
