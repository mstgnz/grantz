package grantz

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"
)

// fakeStore lets the decision rules be tested without a database. The kit's whole point
// is that Store is an interface; this is the first thing that proves it.
type fakeStore struct {
	grants map[int64][]Grant
	err    error
	calls  int
}

func (f *fakeStore) LoadUserGrants(_ context.Context, userID int64) ([]Grant, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.grants[userID], nil
}

func (f *fakeStore) SyncPermissions(context.Context, []Permission) ([]string, error) {
	return nil, nil
}

func newTestAuthorizer(t *testing.T, store Store) *Authorizer {
	t.Helper()
	a, err := New(Config{Store: store})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// TestDenyBeatsAllow is the rule the whole model rests on: a per-user deny removes a
// permission a role granted. If allow ever wins here, revoking access from one person
// silently does nothing and the only visible symptom is that they can still act.
func TestDenyBeatsAllow(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {
			{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true},
			{Key: "invoices.cancel", Effect: EffectDeny},
		},
	}}
	a := newTestAuthorizer(t, store)

	allowed, err := a.Can(context.Background(), 1, "invoices.cancel")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if allowed {
		t.Fatal("deny must win over a role grant")
	}
}

// TestDenyWinsRegardlessOfOrder: the fold must not depend on the order the store returns
// rows in, because SQL makes no such promise.
func TestDenyWinsRegardlessOfOrder(t *testing.T) {
	orders := [][]Grant{
		{{Key: "k.a", Effect: EffectDeny}, {Key: "k.a", Effect: EffectAllow}},
		{{Key: "k.a", Effect: EffectAllow}, {Key: "k.a", Effect: EffectDeny}},
	}
	for i, grants := range orders {
		if fold(grants).Allowed {
			t.Errorf("order %d: deny did not win", i)
		}
	}
}

// TestAbsenceIsDenial: no grant means denied. A permission kit that defaults to open is
// worse than none, because it reads as protection.
func TestAbsenceIsDenial(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{grants: map[int64][]Grant{}})

	allowed, err := a.Can(context.Background(), 99, "invoices.cancel")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if allowed {
		t.Fatal("a user with no grants must be denied")
	}
}

// TestStoreErrorIsNotAnAllow: when grants cannot be resolved the answer is "no", not
// "yes". A database blip must not open every endpoint at once.
func TestStoreErrorIsNotAnAllow(t *testing.T) {
	store := &fakeStore{err: errors.New("connection refused")}
	a := newTestAuthorizer(t, store)

	allowed, err := a.Can(context.Background(), 1, "invoices.cancel")
	if err == nil {
		t.Fatal("expected the store error to surface")
	}
	if allowed {
		t.Fatal("a failed lookup must not report allowed")
	}
}

// TestUserExceptionGrantsWithoutRole covers the other half of the exception table: one
// person gets a permission without cloning a role for them.
func TestUserExceptionGrantsWithoutRole(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {{Key: "invoices.cancel", Effect: EffectAllow}},
	}}
	a := newTestAuthorizer(t, store)

	if err := a.Require(context.Background(), 1, "invoices.cancel"); err != nil {
		t.Fatalf("Require: %v", err)
	}
}

// TestRequireReturnsErrDenied so callers can map it to 403 with errors.Is.
func TestRequireReturnsErrDenied(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})

	err := a.Require(context.Background(), 1, "invoices.cancel")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	// The key has to be in the message; a bare "forbidden" in a log is useless when six
	// permissions guard the same endpoint.
	if got := err.Error(); got == ErrDenied.Error() {
		t.Error("the error should name the permission that was denied")
	}
}

// TestFieldsUnionAcrossRoles: holding two roles gives the wider view, the same way two
// roles' permissions add up rather than intersecting.
func TestFieldsUnionAcrossRoles(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {
			{Key: "invoices.select", Effect: EffectAllow, Fields: []string{"id", "total"}, FromRole: true},
			{Key: "invoices.select", Effect: EffectAllow, Fields: []string{"id", "customer"}, FromRole: true},
		},
	}}
	a := newTestAuthorizer(t, store)

	fields, err := a.Fields(context.Background(), 1, "invoices.select")
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	sort.Strings(fields)
	want := []string{"customer", "id", "total"}
	if len(fields) != len(want) {
		t.Fatalf("fields = %v, want %v", fields, want)
	}
	for i := range want {
		if fields[i] != want[i] {
			t.Fatalf("fields = %v, want %v", fields, want)
		}
	}
}

// TestUnrestrictedGrantWidensRestrictedOne: if one role restricts fields and another does
// not, the user is unrestricted. Returning the narrow list would make adding a role take
// access away, which nobody expects.
func TestUnrestrictedGrantWidensRestrictedOne(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {
			{Key: "invoices.select", Effect: EffectAllow, Fields: []string{"id"}, FromRole: true},
			{Key: "invoices.select", Effect: EffectAllow, FromRole: true},
		},
	}}
	a := newTestAuthorizer(t, store)

	fields, err := a.Fields(context.Background(), 1, "invoices.select")
	if err != nil {
		t.Fatalf("Fields: %v", err)
	}
	if fields != nil {
		t.Fatalf("fields = %v, want nil (unrestricted)", fields)
	}
}

// TestAllFieldsMarker: {"allow":["*"]} is the explicit way to say unrestricted.
func TestAllFieldsMarker(t *testing.T) {
	decision := fold([]Grant{{Key: "k.a", Effect: EffectAllow, Fields: []string{AllFields}}})
	if !decision.Allowed {
		t.Fatal("expected allowed")
	}
	if decision.Fields != nil {
		t.Fatalf("fields = %v, want nil", decision.Fields)
	}
}

// TestFieldsOnDeniedPermissionErrors: a denial must not come back as "allowed, with no
// restriction". That mistake turns a missing permission into full access.
func TestFieldsOnDeniedPermissionErrors(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})

	fields, err := a.Fields(context.Background(), 1, "invoices.select")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if fields != nil {
		t.Fatalf("fields = %v, want nil", fields)
	}
}

// TestScopesAreReturnedNotInterpreted: the kit hands scopes back untouched. Merging them
// here would mean deciding whether two scopes union or intersect, which depends on what
// they mean, which is domain knowledge.
func TestScopesAreReturnedNotInterpreted(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {
			{Key: "invoices.select", Effect: EffectAllow, Scope: map[string]any{"company_id": 12}, FromRole: true},
			{Key: "invoices.select", Effect: EffectAllow, Scope: map[string]any{"company_id": 34}, FromRole: true},
		},
	}}
	a := newTestAuthorizer(t, store)

	scopes, err := a.Scopes(context.Background(), 1, "invoices.select")
	if err != nil {
		t.Fatalf("Scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("got %d scopes, want 2 kept separate", len(scopes))
	}
}

// TestSuperuserBypassesTheStore: the escape hatch must not need a database round trip,
// and must not be reachable by accident (it is nil unless configured).
func TestSuperuserBypassesTheStore(t *testing.T) {
	store := &fakeStore{err: errors.New("must not be called")}
	a, err := New(Config{
		Store:     store,
		Superuser: func(context.Context, int64) bool { return true },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := a.Require(context.Background(), 1, "anything.at.all"); err == nil {
		t.Fatal("a malformed key should still be rejected for a superuser")
	}
	if err := a.Require(context.Background(), 1, "invoices.cancel"); err != nil {
		t.Fatalf("superuser was denied: %v", err)
	}
	if store.calls != 0 {
		t.Errorf("store was consulted %d times, want 0", store.calls)
	}
}

// TestMalformedKeyIsRejected: "invoices", "invoices.", ".cancel" and "a.b.c" are typos,
// and a typo must fail loudly rather than resolve to a permission nobody holds. The
// second kind of failure looks identical to a missing grant and takes hours to find.
func TestMalformedKeyIsRejected(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})

	for _, key := range []string{"", "invoices", "invoices.", ".cancel", "a.b.c"} {
		if _, err := a.Can(context.Background(), 1, key); err == nil {
			t.Errorf("key %q was accepted", key)
		}
	}
}

// TestCacheAvoidsRepeatedLoads and, more importantly, that Invalidate actually drops the
// entry: a permission change that waits for a TTL nobody remembers setting is the usual
// reason people give up on caching authorization.
func TestCacheAvoidsRepeatedLoads(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true}},
	}}
	a, err := New(Config{Store: store, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	for range 3 {
		if _, err := a.Can(ctx, 1, "invoices.cancel"); err != nil {
			t.Fatalf("Can: %v", err)
		}
	}
	if store.calls != 1 {
		t.Fatalf("store called %d times, want 1", store.calls)
	}

	a.Invalidate(ctx, 1)
	if _, err := a.Can(ctx, 1, "invoices.cancel"); err != nil {
		t.Fatalf("Can: %v", err)
	}
	if store.calls != 2 {
		t.Fatalf("store called %d times after invalidate, want 2", store.calls)
	}
}

// TestZeroTTLDisablesCache so a permission problem can be debugged without restarting.
func TestZeroTTLDisablesCache(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{1: {}}}
	a, err := New(Config{Store: store, CacheTTL: 0})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for range 3 {
		if _, err := a.Can(context.Background(), 1, "invoices.cancel"); err != nil {
			t.Fatalf("Can: %v", err)
		}
	}
	if store.calls != 3 {
		t.Fatalf("store called %d times, want 3 (cache disabled)", store.calls)
	}
}

// TestSyncRejectsDuplicateAndMalformedKeys: the catalogue is code, so its mistakes should
// surface at startup rather than as a permission that quietly never matches.
func TestSyncRejectsDuplicateAndMalformedKeys(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})
	ctx := context.Background()

	_, err := a.Sync(ctx, []Permission{{Key: "invoices.cancel"}, {Key: "invoices.cancel"}})
	if err == nil {
		t.Error("duplicate key was accepted")
	}

	if _, err := a.Sync(ctx, []Permission{{Key: "invoices"}}); err == nil {
		t.Error("malformed key was accepted")
	}
}

// TestNewRequiresStore: a nil store must fail at construction, not on the first request.
func TestNewRequiresStore(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted a nil Store")
	}
}

// TestContextHelpersNeedUserIDFunc: using CanCtx without configuring UserID is a wiring
// mistake and should say so, rather than denying every request forever.
func TestContextHelpersNeedUserIDFunc(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})

	_, err := a.CanCtx(context.Background(), "invoices.cancel")
	if err == nil {
		t.Fatal("expected an error about the missing UserID func")
	}
	if errors.Is(err, ErrDenied) {
		t.Error("a wiring mistake must not look like a permission denial")
	}
}

// TestErrNoUserIsDistinctFromDenied so an unauthenticated call can be answered 401.
func TestErrNoUserIsDistinctFromDenied(t *testing.T) {
	a, err := New(Config{
		Store:  &fakeStore{},
		UserID: func(context.Context) (int64, bool) { return 0, false },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = a.RequireCtx(context.Background(), "invoices.cancel")
	if !errors.Is(err, ErrNoUser) {
		t.Fatalf("err = %v, want ErrNoUser", err)
	}
	if errors.Is(err, ErrDenied) {
		t.Error("missing user must not read as denied")
	}
}

// TestPermissionKeyParts covers the accessors the catalogue upsert relies on.
func TestPermissionKeyParts(t *testing.T) {
	p := Permission{Key: "invoices.cancel"}
	if p.Resource() != "invoices" {
		t.Errorf("Resource = %q, want invoices", p.Resource())
	}
	if p.Action() != "cancel" {
		t.Errorf("Action = %q, want cancel", p.Action())
	}
}

// TestUserPermissionsRespectsDeny: the list a UI draws its menu from must go through the
// same fold as an enforcement check. If a denied key showed up here, the button would be
// visible and the endpoint would refuse, which is the exact drift this list exists to
// prevent.
func TestUserPermissionsRespectsDeny(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {
			{Key: "invoices.select", Effect: EffectAllow, FromRole: true},
			{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true},
			{Key: "invoices.cancel", Effect: EffectDeny},
			{Key: "users.create", Effect: EffectAllow},
		},
	}}
	a := newTestAuthorizer(t, store)

	keys, err := a.UserPermissions(context.Background(), 1)
	if err != nil {
		t.Fatalf("UserPermissions: %v", err)
	}

	want := []string{"invoices.select", "users.create"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys = %v, want %v (sorted)", keys, want)
		}
	}
}

// TestUserPermissionsEmptyForUnknownUser: no grants means an empty list, not an error.
// A user with no permissions is a normal state, not a failure.
func TestUserPermissionsEmptyForUnknownUser(t *testing.T) {
	a := newTestAuthorizer(t, &fakeStore{})

	keys, err := a.UserPermissions(context.Background(), 404)
	if err != nil {
		t.Fatalf("UserPermissions: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("keys = %v, want empty", keys)
	}
}
