// Separate module on purpose.
//
// The integration tests need database drivers, and a test dependency in the library's
// own go.mod is not free: Go's minimal version selection would push that driver version
// onto every consumer. A project already using lib/pq would silently get its driver
// upgraded by importing an authorization library, which is not a trade anyone agreed to.
//
// Keeping this in its own module means the published grantz module requires nothing at
// all, and the drivers stay where they belong: in the tests that use them.
module github.com/mstgnz/grantz/sqlstore/integration

go 1.24.0

require (
	github.com/go-sql-driver/mysql v1.10.0
	github.com/lib/pq v1.12.3
	github.com/mstgnz/grantz v0.3.0
)

require github.com/google/uuid v1.6.0

require filippo.io/edwards25519 v1.2.0 // indirect

// Test against the working tree rather than the published tag, so a change to the store
// is exercised before it is tagged.
replace github.com/mstgnz/grantz => ../..
