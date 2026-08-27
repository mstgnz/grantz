// Command basic shows the decision rules without needing a database.
//
// It uses an in-memory Store so you can run it and watch the precedence work:
//
//	go run ./examples/basic
//
// The real thing swaps this Store for sqlstore.New(db); nothing else changes, which is
// the point of keeping the database behind an interface.
package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/mstgnz/grantz"
)

// Permission keys belong in code, not in the database. A typo here fails to compile
// instead of quietly becoming a permission nobody holds.
const (
	InvoiceCreate = "invoices.create"
	InvoiceCancel = "invoices.cancel"
	InvoiceSelect = "invoices.select"
)

var catalogue = []grantz.Permission{
	{Key: InvoiceCreate, Description: "Issue an invoice"},
	{Key: InvoiceCancel, Description: "Cancel an issued invoice"},
	{Key: InvoiceSelect, Description: "List invoices", HasFields: true},
}

// memoryStore is the smallest possible Store. Yours would talk to a database.
type memoryStore struct {
	grants map[int64][]grantz.Grant
}

func (s *memoryStore) LoadUserGrants(_ context.Context, userID int64) ([]grantz.Grant, error) {
	return s.grants[userID], nil
}

func (s *memoryStore) SyncPermissions(_ context.Context, _ []grantz.Permission) ([]string, error) {
	return nil, nil
}

func main() {
	const (
		clerk      int64 = 1 // holds a role that can issue and cancel
		trainee    int64 = 2 // same role, but cancelling was taken away individually
		accountant int64 = 3 // can only read, and only some columns
	)

	store := &memoryStore{grants: map[int64][]grantz.Grant{
		clerk: {
			{Key: InvoiceCreate, Effect: grantz.EffectAllow, FromRole: true},
			{Key: InvoiceCancel, Effect: grantz.EffectAllow, FromRole: true},
		},
		trainee: {
			{Key: InvoiceCreate, Effect: grantz.EffectAllow, FromRole: true},
			{Key: InvoiceCancel, Effect: grantz.EffectAllow, FromRole: true},
			// One row instead of cloning the role. This is the answer to role explosion.
			{Key: InvoiceCancel, Effect: grantz.EffectDeny},
		},
		accountant: {
			{
				Key:      InvoiceSelect,
				Effect:   grantz.EffectAllow,
				Fields:   []string{"id", "invoice_number", "invoice_date"},
				Scope:    map[string]any{"company_id": 12},
				FromRole: true,
			},
		},
	}}

	authz, err := grantz.New(grantz.Config{Store: store})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	if _, err := authz.Sync(ctx, catalogue); err != nil {
		panic(err)
	}

	fmt.Println("-- can they cancel an invoice?")
	for _, u := range []struct {
		id   int64
		name string
	}{{clerk, "clerk"}, {trainee, "trainee"}, {accountant, "accountant"}} {
		allowed, err := authz.Can(ctx, u.id, InvoiceCancel)
		if err != nil {
			panic(err)
		}
		fmt.Printf("  %-11s %v\n", u.name, allowed)
	}

	fmt.Println("\n-- Require returns a typed error, map it to your 403")
	err = authz.Require(ctx, trainee, InvoiceCancel)
	fmt.Printf("  trainee: %v (ErrDenied: %v)\n", err, errors.Is(err, grantz.ErrDenied))

	fmt.Println("\n-- field restriction")
	fields, err := authz.Fields(ctx, accountant, InvoiceSelect)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  accountant may read: %v\n", fields)

	fields, err = authz.Fields(ctx, clerk, InvoiceSelect)
	fmt.Printf("  clerk: fields=%v err=%v\n", fields, err)
	fmt.Println("  (a denial is an error, never an empty list read as unrestricted)")

	fmt.Println("\n-- scope is handed back, never interpreted")
	scopes, err := authz.Scopes(ctx, accountant, InvoiceSelect)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  accountant scopes: %v\n", scopes)
	fmt.Println("  your query decides what company_id means; the kit does not")

	fmt.Println("\n-- what a UI would ask for once, after login")
	keys, err := authz.UserPermissions(ctx, trainee)
	if err != nil {
		panic(err)
	}
	fmt.Printf("  trainee holds: %v\n", keys)
}
