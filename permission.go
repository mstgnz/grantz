package grantz

import (
	"errors"
	"fmt"
	"strings"
)

// Permission is one thing the system can do, declared in code.
//
// The catalogue lives in source rather than in the database on purpose: a typo becomes a
// compile error instead of a silent 403, a new capability shows up in code review, and
// every key is greppable. What an administrator edits is the mapping from roles to these
// keys, which is data and belongs in the database.
type Permission struct {
	// Key is "<resource>.<action>", e.g. "invoices.cancel".
	Key string
	// Description is shown in the admin UI that lists permissions.
	Description string
	// HasFields marks a permission for which field-level restrictions make sense.
	// "select" and "update" do; "delete" and business verbs like "cancel" do not, because
	// there is no field to restrict, the whole action either happens or it does not.
	HasFields bool
}

// Resource is the part before the dot: "invoices" in "invoices.cancel".
func (p Permission) Resource() string {
	resource, _, _ := splitKey(p.Key)
	return resource
}

// Action is the part after the dot: "cancel" in "invoices.cancel".
func (p Permission) Action() string {
	_, action, _ := splitKey(p.Key)
	return action
}

// Validate reports whether the key has the required "<resource>.<action>" shape.
func (p Permission) Validate() error {
	if _, _, err := splitKey(p.Key); err != nil {
		return err
	}
	return nil
}

func splitKey(key string) (resource, action string, err error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", errors.New("grantz: permission key is empty")
	}
	resource, action, found := strings.Cut(key, ".")
	if !found || resource == "" || action == "" {
		return "", "", fmt.Errorf("grantz: permission key %q must be \"<resource>.<action>\"", key)
	}
	if strings.Contains(action, ".") {
		return "", "", fmt.Errorf("grantz: permission key %q has more than one dot", key)
	}
	return resource, action, nil
}

// Effect is what a user-level exception does to a permission.
type Effect string

const (
	// EffectAllow grants the permission even when no role carries it.
	EffectAllow Effect = "allow"
	// EffectDeny removes the permission even when a role carries it. Deny always wins.
	EffectDeny Effect = "deny"
)

// AllFields is the explicit "no restriction" marker inside a field allow-list.
const AllFields = "*"

// Grant is one resolved row on the way to a decision: either a role's permission or a
// user-level exception. The store returns these and the authorizer folds them into a
// single answer per key.
type Grant struct {
	Key    string
	Effect Effect
	// Fields is the allow-list for this grant. Nil means unrestricted. A list containing
	// AllFields also means unrestricted, and is how an administrator says so explicitly.
	Fields []string
	// Scope is the role's optional narrowing, handed back to the caller untouched.
	// The kit never interprets it: whether a record falls inside a scope is domain
	// knowledge, and putting that comparison here is how an authorization kit turns
	// into a query builder.
	Scope map[string]any
	// FromRole is false for a user-level exception. Only used to keep deny precedence
	// readable in tests and debugging output.
	FromRole bool
}

// Decision is the folded result for one permission key.
type Decision struct {
	Allowed bool
	// Fields is nil when every field is allowed.
	Fields []string
	// Scopes carries every scope that granted this permission. More than one role can
	// grant the same key with different scopes, and the caller decides how to combine
	// them; collapsing them here would silently widen or narrow access.
	Scopes []map[string]any
}

// fold turns the grants for one key into a decision.
//
// Precedence, fixed and not configurable:
//  1. any deny wins, whatever granted it;
//  2. otherwise any allow grants;
//  3. otherwise denied. Absence of a grant is a denial, never a default-open.
//
// Field lists from several allowing grants are unioned: holding two roles gives you the
// wider view, which is what "roles add up" means everywhere else.
func fold(grants []Grant) Decision {
	decision := Decision{}
	unrestricted := false
	fieldSet := map[string]struct{}{}

	for _, g := range grants {
		if g.Effect == EffectDeny {
			return Decision{Allowed: false}
		}
	}

	for _, g := range grants {
		if g.Effect != EffectAllow {
			continue
		}
		decision.Allowed = true
		if g.Scope != nil {
			decision.Scopes = append(decision.Scopes, g.Scope)
		}
		if len(g.Fields) == 0 {
			unrestricted = true
			continue
		}
		for _, f := range g.Fields {
			if f == AllFields {
				unrestricted = true
				break
			}
			fieldSet[f] = struct{}{}
		}
	}

	if !decision.Allowed || unrestricted {
		return decision
	}

	decision.Fields = make([]string, 0, len(fieldSet))
	for f := range fieldSet {
		decision.Fields = append(decision.Fields, f)
	}
	return decision
}
