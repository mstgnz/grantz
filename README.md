# grantz

[![CI](https://github.com/mstgnz/grantz/actions/workflows/ci.yml/badge.svg)](https://github.com/mstgnz/grantz/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/mstgnz/grantz.svg)](https://pkg.go.dev/github.com/mstgnz/grantz)
[![Go Report Card](https://goreportcard.com/badge/github.com/mstgnz/grantz)](https://goreportcard.com/report/github.com/mstgnz/grantz)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Authorization for Go services, keyed on **business verbs** rather than tables.

```go
if err := authz.RequireCtx(ctx, "invoices.cancel"); err != nil {
    return forbidden(err)
}
```

**Zero dependencies.** `go.mod` requires nothing, which matters more than it sounds: a
require line in a library is forced onto every consumer through minimal version
selection, so even a test-only driver would silently upgrade the driver of a project that
already used one. The integration tests that need Postgres live in their own module for
exactly that reason.

Your database sits behind a two-method interface, so GORM, sqlx and raw `database/sql`
projects all fit without the library knowing which one you use.

```bash
go get github.com/mstgnz/grantz
```

## Why verbs, not tables

A table-level grant cannot express a business rule. "May cancel an invoice" and "may
update the invoices table" are different permissions: the second also covers the
accounting integration writing a number back, a status correction, and a migration. Once
authorization is expressed in table terms you no longer know what you allowed.

The exception is a platform whose data model the customer defines (Salesforce, Airtable,
Hasura). Those have no choice but to grant per table and per column, because they cannot
know the verbs in advance. An application that knows its own domain can do better.

Field-level restrictions still exist here, as an **optional** narrowing of a verb you
already hold. The schema carries them from day one; use them when a permission needs them
and ignore them otherwise.

## Model

RBAC, with the two additions that plain RBAC handles badly:

| Piece                      | What it solves                                           |
| -------------------------- | -------------------------------------------------------- |
| roles → permissions        | the base model                                           |
| per-user allow/deny        | role explosion: one person needing slightly more or less |
| scope on a role assignment | multi-tenancy, without a role per tenant                 |
| field allow-list           | "sees the invoice but not the amounts"                   |

Not ABAC: nothing is computed from attributes at decision time. A `conditions jsonb`
column sits unused in the schema so adding attribute rules later is a code change rather
than a migration.

Precedence is fixed and not configurable:

1. any **deny** wins, whatever granted it
2. otherwise any **allow** grants
3. otherwise **denied** — absence of a grant is a denial, never a default-open

## Quick start

Run `migrations/001_init.sql`. Every table is prefixed `grantz_`, so it drops into a
database that already has its own `users`, `roles` or `permissions` without colliding.

The library does not own users: `grantz_user_roles.user_id` is a plain `bigint` with no
foreign key, because where users live is your decision.

Declare the catalogue in code, not in the database. A typo then fails at startup instead
of becoming a permission nobody holds, and a new capability shows up in code review.

```go
var Permissions = []grantz.Permission{
    {Key: "invoices.select", Description: "List invoices", HasFields: true},
    {Key: "invoices.create", Description: "Issue an invoice"},
    {Key: "invoices.cancel", Description: "Cancel an issued invoice"},
}
```

Wire it once:

```go
sqlDB, _ := gormDB.DB() // or your *sql.DB directly

authz, err := grantz.New(grantz.Config{
    Store:    sqlstore.New(sqlDB),
    UserID:   func(ctx context.Context) (int64, bool) {
        u, ok := ctx.Value(userKey).(*User)
        if !ok { return 0, false }
        return u.ID, true
    },
    CacheTTL: time.Minute,
    Superuser: func(ctx context.Context, id int64) bool { return isAdmin(ctx) },
})

orphans, err := authz.Sync(ctx, Permissions)
```

`orphans` are keys the database still carries but the code no longer declares. They are
reported, never deleted: a rollback to an older binary would otherwise cascade away the
role mappings an administrator configured.

Then ask, in a handler:

```go
if err := authz.RequireCtx(ctx, "invoices.cancel"); err != nil {
    // errors.Is(err, grantz.ErrDenied)  -> 403
    // errors.Is(err, grantz.ErrNoUser)  -> 401
    return respond(err)
}
```

Or as middleware. Plain `net/http`, so chi takes it directly:

```go
r.With(authz.Middleware("invoices.cancel", writeError)).
  Post("/invoices/{id}/cancel", handler)
```

Two runnable examples are in [`examples/`](examples): `basic` shows the decision rules
with no database, `httpserver` shows the middleware and the `/me/permissions` pattern.

```bash
go run ./examples/basic
```

## Field restrictions

```go
fields, err := authz.Fields(ctx, userID, "invoices.select")
// nil        → every field, no restriction
// ["id","x"] → only these
// ErrDenied  → the user does not hold the permission at all
```

`nil` and an empty list are not the same, and the difference matters: `nil` means
unrestricted, an empty list would mean "may act, on nothing". `Fields` returns
`ErrDenied` rather than an empty list for a permission the user lacks, so a denial can
never be mistaken for an unrestricted result.

Restrictions are **allow-lists**. A column added to the table later stays hidden until
someone exposes it deliberately; with a deny-list it would leak the moment it was added.
`{"allow": ["*"]}` is the explicit "all fields" form.

Two roles granting the same permission **union** their field lists, and an unrestricted
grant beats a restricted one. Adding a role should never take access away.

## Scopes

```go
scopes, err := authz.Scopes(ctx, userID, "invoices.select")
// [{"company_id": 12}]
```

Scopes come back untouched and are never interpreted. Whether a record falls inside a
scope is domain knowledge, and putting that comparison in the library is how a permission
kit turns into a query builder. Several scopes come back separately because whether they
union or intersect depends on what they mean.

## Feeding a UI

```go
keys, err := authz.UserPermissionsCtx(ctx)  // ["invoices.create", "invoices.select"]
```

Expose this as `GET /me/permissions`, let the client fetch it once after login and draw
its menus and buttons from it. Because both sides read the same rows, a hidden button and
a refusing endpoint cannot drift apart.

It is a convenience, never an authority. Every endpoint still checks for itself; the list
only decides what gets drawn.

## What this does not do

- **Record-level checks.** "May cancel invoices" is answered here; "may cancel THIS
  invoice" needs the row, so it belongs in your service after the row is read. Middleware
  runs before that and cannot do it.
- **Own your users.** You pass a user id.
- **Talk to a specific database.** Everything goes through `Store`.
- **Menus and screens.** A menu row should point at a permission key; the navigation
  structure is your UI's business.
- **Cross-instance cache invalidation.** The default cache is per-process, so an
  invalidation on one instance does not reach the others. Put Redis behind the `Cache`
  interface, or keep the TTL short.

## Your own Store

Two methods:

```go
type Store interface {
    LoadUserGrants(ctx context.Context, userID int64) ([]Grant, error)
    SyncPermissions(ctx context.Context, perms []Permission) (orphans []string, err error)
}
```

`LoadUserGrants` must return denials as well as allowances. Filtering them out quietly
breaks deny precedence, and the symptom is that revoking one person's access does
nothing.

[`sqlstore`](sqlstore) is the Postgres implementation and is about 200 lines; another
engine is a file that size, not a fork.

## Failure modes it is built against

- A store error resolves to **denied**, never allowed. A database blip must not open
  every endpoint at once.
- A malformed key (`invoices`, `a.b.c`) is an **error**, not a permission nobody holds.
  The second kind of failure is indistinguishable from a missing grant and takes hours
  to find.
- An unparseable field restriction is an **error**, not "unrestricted". A malformed
  restriction that reads as no restriction is how data gets exposed.
- No user in context returns `ErrNoUser`, distinct from `ErrDenied`, so the caller can
  answer 401 rather than 403.
- Deny precedence does not depend on the order rows come back in, because SQL makes no
  such promise.

Each of those has a test named after it.

## Tests

```bash
go test ./...                                    # no database needed

docker compose up -d                             # for the SQL suite
cd sqlstore/integration
GRANTZ_TEST_DSN="postgres://grantz:grantz@localhost:5433/grantz?sslmode=disable" \
  go test -tags=integration ./...
```

The SQL suite is a separate module under `sqlstore/integration`, so the Postgres driver
it needs never reaches this module's `go.mod` and therefore never reaches yours. CI
enforces that with a `go list -m all` check on every push.

## Schema

Five tables, all prefixed:

| Table                     | Holds                                           |
| ------------------------- | ----------------------------------------------- |
| `grantz_permissions`      | the catalogue, written by `Sync` from your code |
| `grantz_roles`            | roles                                           |
| `grantz_role_permissions` | role → permission, with the optional field list |
| `grantz_user_roles`       | user → role, with the optional scope            |
| `grantz_user_permissions` | per-user allow/deny exception                   |

Do not expose these through a generic CRUD layer. A user who can edit their own
permissions is not authorized.

## License

MIT
