//go:build integration

package integration

import (
	"testing"

	_ "github.com/go-sql-driver/mysql"
)

// TestMySQL runs the same suite against MySQL 8, which is what sqlstore.NewMySQL builds.
//
// Same assertions, no engine-specific expectations: the differences belong in the store's
// dialect, and a behaviour that only holds on one engine is the bug this exists to catch.
func TestMySQL(t *testing.T) { runSuite(t, mysql) }
