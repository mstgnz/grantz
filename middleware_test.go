package grantz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type ctxKey string

const userKey ctxKey = "user"

func withUser(id int64) context.Context {
	return context.WithValue(context.Background(), userKey, id)
}

func userFromCtx(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userKey).(int64)
	return id, ok
}

func middlewareAuthorizer(t *testing.T, grants map[int64][]Grant) *Authorizer {
	t.Helper()
	a, err := New(Config{
		Store:  &fakeStore{grants: grants},
		UserID: userFromCtx,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// TestMiddlewareBlocksAndPasses is the basic contract; the handler must not run at all
// when the permission is missing, because "runs but returns 403" still means the side
// effect happened.
func TestMiddlewareBlocksAndPasses(t *testing.T) {
	a := middlewareAuthorizer(t, map[int64][]Grant{
		7: {{Key: "invoices.cancel", Effect: EffectAllow, FromRole: true}},
	})

	var handlerRan bool
	handler := a.Middleware("invoices.cancel", nil)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			handlerRan = true
			w.WriteHeader(http.StatusOK)
		},
	))

	t.Run("allowed user reaches the handler", func(t *testing.T) {
		handlerRan = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(withUser(7))

		handler.ServeHTTP(rec, req)

		if !handlerRan {
			t.Error("handler did not run")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("user without the permission is stopped before the handler", func(t *testing.T) {
		handlerRan = false
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/x", nil).WithContext(withUser(8))

		handler.ServeHTTP(rec, req)

		if handlerRan {
			t.Error("handler ran despite the denial")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}

// TestMiddlewareSeparates401From403: a request with no user is unauthenticated, not
// forbidden. Collapsing the two costs the client the ability to tell "log in again"
// apart from "you cannot do this".
func TestMiddlewareSeparates401From403(t *testing.T) {
	a := middlewareAuthorizer(t, nil)

	handler := a.Middleware("invoices.cancel", nil)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { t.Error("handler must not run") },
	))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a request with no user", rec.Code)
	}
}

// TestMiddlewareUsesTheErrorWriter so a host application keeps its own response envelope
// instead of the kit's plain text.
func TestMiddlewareUsesTheErrorWriter(t *testing.T) {
	a := middlewareAuthorizer(t, nil)

	var seen error
	writer := func(w http.ResponseWriter, _ *http.Request, err error) {
		seen = err
		w.WriteHeader(http.StatusTeapot)
	}

	handler := a.Middleware("invoices.cancel", writer)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { t.Error("handler must not run") },
	))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(withUser(1))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want the writer's 418", rec.Code)
	}
	if !errors.Is(seen, ErrDenied) {
		t.Errorf("writer got %v, want ErrDenied", seen)
	}
}

// TestMiddlewareDeniesOnStoreFailure: an unresolvable permission is a denial. A store
// outage must not open the endpoint.
func TestMiddlewareDeniesOnStoreFailure(t *testing.T) {
	a, err := New(Config{
		Store:  &fakeStore{err: errors.New("db down")},
		UserID: userFromCtx,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	handler := a.Middleware("invoices.cancel", nil)(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { t.Error("handler must not run") },
	))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(withUser(1))
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestCacheEntryExpires drives the clock rather than sleeping, so the TTL path is covered
// without making the suite slow.
func TestCacheEntryExpires(t *testing.T) {
	cache := NewMemoryCache(time.Minute).(*memoryCache[int64])
	now := time.Now()
	cache.now = func() time.Time { return now }
	ctx := context.Background()

	cache.Set(ctx, 1, []Grant{{Key: "a.b", Effect: EffectAllow}})
	if _, ok := cache.Get(ctx, 1); !ok {
		t.Fatal("entry missing immediately after Set")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := cache.Get(ctx, 1); ok {
		t.Fatal("expired entry was still served")
	}
}

// TestInvalidateAll: editing a role affects every user holding it, and the kit does not
// track who those are, so the whole cache has to go.
func TestInvalidateAll(t *testing.T) {
	store := &fakeStore{grants: map[int64][]Grant{
		1: {{Key: "a.b", Effect: EffectAllow, FromRole: true}},
		2: {{Key: "a.b", Effect: EffectAllow, FromRole: true}},
	}}
	a, err := New(Config{Store: store, CacheTTL: time.Minute})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	_, _ = a.Can(ctx, 1, "a.b")
	_, _ = a.Can(ctx, 2, "a.b")
	if store.calls != 2 {
		t.Fatalf("store called %d times, want 2", store.calls)
	}

	a.InvalidateAll(ctx)

	_, _ = a.Can(ctx, 1, "a.b")
	_, _ = a.Can(ctx, 2, "a.b")
	if store.calls != 4 {
		t.Fatalf("store called %d times after InvalidateAll, want 4", store.calls)
	}
}
