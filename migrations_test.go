package grantz

import (
	"os"
	"strings"
	"testing"
)

// The four schema files. One engine, one id type each; a project runs exactly one of them.
const (
	pgSchema        = "migrations/001_init_postgres.sql"
	pgUUIDSchema    = "migrations/001_init_postgres_uuid.sql"
	mysqlSchema     = "migrations/001_init_mysql.sql"
	mysqlUUIDSchema = "migrations/001_init_mysql_uuid.sql"
)

// ddlLines strips comments and blank lines and collapses whitespace, leaving only the
// statements. Comparing those is the point: the schema files are allowed to explain
// themselves differently, they are not allowed to define different tables.
func ddlLines(t *testing.T, path string) []string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" || strings.HasPrefix(line, "--") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// assertOnlyTheUserIDColumnsDiffer compares two schema files line by line and allows
// exactly two differences: the columns that carry a user id.
//
// This guards the one real cost of shipping an id variant as a second file: the two
// drifting apart. A column added to one and forgotten in the other would only surface as
// a runtime SQL error in whichever project happened to use that variant, which is the
// worst place to find out.
func assertOnlyTheUserIDColumnsDiffer(t *testing.T, basePath, variantPath, baseType, variantType string) {
	t.Helper()

	base := ddlLines(t, basePath)
	variant := ddlLines(t, variantPath)

	if len(base) != len(variant) {
		t.Fatalf("%s and %s have %d and %d statement lines; they must differ only in the user_id columns",
			basePath, variantPath, len(base), len(variant))
	}

	differences := 0
	for i := range base {
		if base[i] == variant[i] {
			continue
		}
		differences++
		if !strings.HasPrefix(base[i], "user_id "+baseType) || !strings.HasPrefix(variant[i], "user_id "+variantType) {
			t.Errorf("line %d differs beyond the user id type:\n  %s: %s\n  %s: %s",
				i, baseType, base[i], variantType, variant[i])
		}
	}
	if differences != 2 {
		t.Fatalf("%s vs %s: expected exactly 2 differing lines (the two user_id columns), got %d",
			basePath, variantPath, differences)
	}
}

// TestUUIDSchemaMatchesTheDefaultOne: Postgres bigint against Postgres uuid.
func TestUUIDSchemaMatchesTheDefaultOne(t *testing.T) {
	assertOnlyTheUserIDColumnsDiffer(t, pgSchema, pgUUIDSchema, "bigint", "uuid")
}

// TestMySQLUUIDSchemaMatchesTheMySQLOne: MySQL bigint against MySQL char(36).
func TestMySQLUUIDSchemaMatchesTheMySQLOne(t *testing.T) {
	assertOnlyTheUserIDColumnsDiffer(t, mysqlSchema, mysqlUUIDSchema, "bigint", "char(36)")
}

type schemaTable struct {
	name    string
	columns []string
}

// tableColumns reads the CREATE TABLE blocks and returns each table with its columns, in
// declaration order. Constraint and index lines are skipped: those are where the engines
// legitimately differ, and this parser exists to compare the part where they must not.
func tableColumns(t *testing.T, path string) []schemaTable {
	t.Helper()

	// Matched case-sensitively, and that is load-bearing: MySQL's index line starts with
	// the keyword KEY, while the catalogue's primary key column is called key. Both files
	// write keywords in upper case and identifiers in lower case, so the case tells them
	// apart. A future lower-case "primary key (...)" would be read as a column and fail
	// this test loudly, which is the right way round.
	notAColumn := map[string]bool{
		"PRIMARY": true, "UNIQUE": true, "KEY": true, "INDEX": true,
		"CONSTRAINT": true, "FOREIGN": true, "CHECK": true,
	}

	var (
		tables  []schemaTable
		current *schemaTable
	)
	for _, line := range ddlLines(t, path) {
		if strings.HasPrefix(line, "CREATE TABLE") {
			// ... IF NOT EXISTS <name> (
			fields := strings.Fields(line)
			tables = append(tables, schemaTable{name: fields[len(fields)-2]})
			current = &tables[len(tables)-1]
			continue
		}
		if current == nil {
			continue
		}
		if strings.HasPrefix(line, ")") {
			current = nil
			continue
		}
		first := strings.Fields(line)[0]
		if notAColumn[first] {
			continue
		}
		current.columns = append(current.columns, strings.Trim(first, "`\""))
	}
	return tables
}

// TestEveryEngineDefinesTheSameTablesAndColumns is what keeps a second engine from
// becoming a second product.
//
// The store reads the same column names whatever it is talking to, so a column that
// exists in one schema and not another is not a portability wrinkle, it is a query that
// fails at runtime for the projects on that engine only. Types are allowed to differ
// (jsonb against json, serial against AUTO_INCREMENT); names and order are not.
func TestEveryEngineDefinesTheSameTablesAndColumns(t *testing.T) {
	reference := tableColumns(t, pgSchema)
	if len(reference) != 5 {
		t.Fatalf("parsed %d tables from %s, want 5", len(reference), pgSchema)
	}

	for _, path := range []string{pgUUIDSchema, mysqlSchema, mysqlUUIDSchema} {
		got := tableColumns(t, path)
		if len(got) != len(reference) {
			t.Errorf("%s defines %d tables, %s defines %d", path, len(got), pgSchema, len(reference))
			continue
		}
		for i, want := range reference {
			if got[i].name != want.name {
				t.Errorf("%s table %d is %q, want %q", path, i, got[i].name, want.name)
				continue
			}
			if strings.Join(got[i].columns, ",") != strings.Join(want.columns, ",") {
				t.Errorf("%s table %s has columns %v, want %v",
					path, want.name, got[i].columns, want.columns)
			}
		}
	}
}

// TestMySQLSchemasDeclareConstraintsMySQLActuallyEnforces covers two ways a MySQL
// migration can succeed and leave nothing behind.
//
// A column-level REFERENCES clause is parsed by MySQL and then ignored, so the foreign
// key silently does not exist. MyISAM does the same with a table-level one. Both would
// pass every test in this repository and only show up the day a delete failed to cascade.
func TestMySQLSchemasDeclareConstraintsMySQLActuallyEnforces(t *testing.T) {
	for _, path := range []string{mysqlSchema, mysqlUUIDSchema} {
		var tables int
		for _, line := range ddlLines(t, path) {
			if strings.HasPrefix(line, "CREATE TABLE") {
				tables++
			}
			if strings.Contains(line, "REFERENCES") && !strings.HasPrefix(line, "FOREIGN KEY") {
				t.Errorf("%s: column-level REFERENCES is parsed and ignored by MySQL, "+
					"use a table-level FOREIGN KEY:\n  %s", path, line)
			}
			if strings.HasPrefix(line, ")") && !strings.Contains(line, "ENGINE=InnoDB") {
				t.Errorf("%s: a table is not declared ENGINE=InnoDB, so its foreign keys "+
					"may be accepted and ignored:\n  %s", path, line)
			}
		}
		if tables != 5 {
			t.Errorf("%s declares %d tables, want 5", path, tables)
		}
	}
}
