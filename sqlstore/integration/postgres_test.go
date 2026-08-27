//go:build integration

package integration

import (
	"testing"

	_ "github.com/lib/pq"
)

// TestPostgres runs the whole suite against Postgres, which is what sqlstore.New builds.
func TestPostgres(t *testing.T) { runSuite(t, postgres) }
