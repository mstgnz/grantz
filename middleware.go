package grantz

import (
	"errors"
	"net/http"
)

// ErrorWriter turns an authorization failure into a response.
//
// The kit has no opinion about your response envelope, so it asks for one function
// instead of guessing at a JSON shape. Without it, the middleware falls back to plain
// 401/403 with no body.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, err error)

// Middleware returns a handler wrapper that rejects requests whose user lacks the
// permission.
//
// The signature is plain net/http, so chi and anything else that speaks
// func(http.Handler) http.Handler takes it directly. Gin and Echo need a three-line
// adapter, which is the right trade: the kit stays free of a router dependency.
//
// Note what this does and does not cover. It answers "may this user perform this action
// at all", which is the coarse half of authorization. Whether they may perform it on
// THIS record needs the record, which the middleware has not loaded yet; that check
// belongs in the handler or the service, after the row is read.
func (a *AuthorizerOf[T]) Middleware(key string, onError ErrorWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.RequireCtx(r.Context(), key); err != nil {
				writeAuthzError(w, r, err, onError)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAuthzError(w http.ResponseWriter, r *http.Request, err error, onError ErrorWriter) {
	if onError != nil {
		onError(w, r, err)
		return
	}
	// A missing user is 401 and a missing permission is 403. Collapsing both into one
	// status is a common shortcut and it costs you the ability to tell "log in again"
	// apart from "you cannot do this".
	if errors.Is(err, ErrNoUser) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if errors.Is(err, ErrDenied) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Anything else is a failure to resolve, and an unresolved permission is a denial.
	http.Error(w, "forbidden", http.StatusForbidden)
}
