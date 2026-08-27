package grantz

import (
	"os"
	"strings"
	"testing"
)

// ddlLines strips comments and blank lines and collapses whitespace, leaving only the
// statements. Comparing those is the point: the two schema files are allowed to explain
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

// TestUUIDSchemaMatchesTheDefaultOne guards the one real cost of shipping the uuid
// variant as a second file: the two drifting apart. A column added to the bigint schema
// and forgotten in the uuid one would only surface as a runtime SQL error in whichever
// project happened to use uuids, which is the worst place to find out.
//
// The only difference allowed is the type of the two user_id columns.
func TestUUIDSchemaMatchesTheDefaultOne(t *testing.T) {
	base := ddlLines(t, "migrations/001_init.sql")
	uuid := ddlLines(t, "migrations/001_init_uuid.sql")

	if len(base) != len(uuid) {
		t.Fatalf("schemas have %d and %d statements lines; they must differ only in the user_id columns",
			len(base), len(uuid))
	}

	differences := 0
	for i := range base {
		if base[i] == uuid[i] {
			continue
		}
		differences++
		if !strings.HasPrefix(base[i], "user_id bigint") || !strings.HasPrefix(uuid[i], "user_id uuid") {
			t.Errorf("line %d differs beyond the user id type:\n  bigint: %s\n  uuid:   %s", i, base[i], uuid[i])
		}
	}
	if differences != 2 {
		t.Fatalf("expected exactly 2 differing lines (the two user_id columns), got %d", differences)
	}
}
