// Command httpserver shows the middleware and the /me/permissions pattern.
//
//	go run ./examples/httpserver
//	curl -H 'X-User-Id: 1' localhost:8080/me/permissions
//	curl -XPOST -H 'X-User-Id: 1' localhost:8080/invoices/1/cancel   # 200
//	curl -XPOST -H 'X-User-Id: 2' localhost:8080/invoices/1/cancel   # 403
//	curl -XPOST localhost:8080/invoices/1/cancel                     # 401
//
// The header is a stand-in for whatever your authentication puts in the context; grantz
// never learns how you identify users, it just calls the function you supply.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/mstgnz/grantz"
)

const (
	InvoiceCreate = "invoices.create"
	InvoiceCancel = "invoices.cancel"
)

type ctxKey string

const userIDKey ctxKey = "user_id"

type memoryStore struct{ grants map[int64][]grantz.Grant }

func (s *memoryStore) LoadUserGrants(_ context.Context, id int64) ([]grantz.Grant, error) {
	return s.grants[id], nil
}
func (s *memoryStore) SyncPermissions(context.Context, []grantz.Permission) ([]string, error) {
	return nil, nil
}

// authenticate is your login, reduced to a header. It only establishes WHO the caller is;
// what they may do is a separate question and grantz answers that one.
func authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("X-User-Id")
		if raw == "" {
			next.ServeHTTP(w, r) // no user; grantz will answer 401
			return
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			http.Error(w, "bad user id", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey, id)))
	})
}

// writeError keeps the kit out of your response envelope. Without it the middleware
// falls back to plain text, which is fine for a prototype and wrong for an API.
func writeError(w http.ResponseWriter, _ *http.Request, err error) {
	status := http.StatusForbidden
	message := "you may not do that"
	if errors.Is(err, grantz.ErrNoUser) {
		status = http.StatusUnauthorized
		message = "sign in first"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func main() {
	store := &memoryStore{grants: map[int64][]grantz.Grant{
		1: {
			{Key: InvoiceCreate, Effect: grantz.EffectAllow, FromRole: true},
			{Key: InvoiceCancel, Effect: grantz.EffectAllow, FromRole: true},
		},
		2: {
			{Key: InvoiceCreate, Effect: grantz.EffectAllow, FromRole: true},
		},
	}}

	authz, err := grantz.New(grantz.Config{
		Store: store,
		UserID: func(ctx context.Context) (int64, bool) {
			id, ok := ctx.Value(userIDKey).(int64)
			return id, ok
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// The middleware answers "may this user cancel invoices at all". Whether they may
	// cancel THIS one needs the row, so that check belongs in the handler below, after
	// it is loaded. Middleware runs too early to know.
	mux.Handle("POST /invoices/{id}/cancel",
		authz.Middleware(InvoiceCancel, writeError)(http.HandlerFunc(cancelInvoice)))

	// What a UI asks for once after login, so it can draw the right buttons. It is a
	// convenience, not an authority: the endpoint above still checks for itself.
	mux.HandleFunc("GET /me/permissions", func(w http.ResponseWriter, r *http.Request) {
		keys, err := authz.UserPermissionsCtx(r.Context())
		if err != nil {
			writeError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"permissions": keys})
	})

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", authenticate(mux)))
}

func cancelInvoice(w http.ResponseWriter, r *http.Request) {
	// Record-level check goes here: load the invoice, compare it against the scope from
	// authz.Scopes if you use scopes, then act.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"cancelled": r.PathValue("id"),
	})
}
