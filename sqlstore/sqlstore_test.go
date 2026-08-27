package sqlstore

import (
	"testing"

	"github.com/mstgnz/grantz"
)

// TestDecodeFields covers the parsing of the {"allow": [...]} column.
//
// The malformed case is the one that matters. A restriction that fails to parse must be
// an error, never an empty list read as "no restriction": that mistake turns a typo in a
// jsonb column into full field access, and nothing in the request looks wrong.
func TestDecodeFields(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "null column means unrestricted", raw: "", want: nil},
		{name: "allow list", raw: `{"allow":["id","total"]}`, want: []string{"id", "total"}},
		{name: "star marker is passed through", raw: `{"allow":["*"]}`, want: []string{grantz.AllFields}},
		{name: "empty object yields no fields", raw: `{}`, want: nil},
		{name: "malformed json errors", raw: `{"allow":`, wantErr: true},
		{name: "wrong type errors", raw: `{"allow":"id"}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeFields([]byte(tt.raw))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("decodeFields(%q) = %v, want an error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeFields(%q): %v", tt.raw, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestDecodeScope: a scope is handed to the caller untouched, so the only job here is to
// parse it or fail loudly.
func TestDecodeScope(t *testing.T) {
	got, err := decodeScope([]byte(`{"company_id":12}`))
	if err != nil {
		t.Fatalf("decodeScope: %v", err)
	}
	if got["company_id"] != float64(12) {
		t.Fatalf("company_id = %v (%T), want 12", got["company_id"], got["company_id"])
	}

	if got, err := decodeScope(nil); err != nil || got != nil {
		t.Fatalf("nil column: got %v, %v; want nil, nil", got, err)
	}

	if _, err := decodeScope([]byte(`not json`)); err == nil {
		t.Fatal("malformed scope was accepted")
	}
}

// TestNewReturnsStore is a compile-time guarantee more than a test: it pins that Store
// satisfies grantz.Store, so a change to the interface breaks here rather than at the
// call site in someone else's project. Both engines return the same type; only the SQL
// behind it differs.
func TestNewReturnsStore(t *testing.T) {
	var _ grantz.Store = New(nil)
	var _ grantz.Store = NewMySQL(nil)
}
