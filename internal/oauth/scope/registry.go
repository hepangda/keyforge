// Package scope is the declarative catalog of OAuth scopes keyforge
// recognises, together with the claim mapping each implies for ID tokens
// and the UserInfo endpoint.
//
// v1 ships a fixed catalog; a future milestone (M7) layers per-client
// allowlists and per-resource audience policy on top.
package scope

import "strings"

// Claim is the name of an OIDC claim produced by a scope.
type Claim = string

// Common claims, kept as constants to avoid stringly-typed sprawl.
const (
	ClaimSub               Claim = "sub"
	ClaimEmail             Claim = "email"
	ClaimEmailVerified     Claim = "email_verified"
	ClaimName              Claim = "name"
	ClaimPreferredUsername Claim = "preferred_username"
	ClaimPicture           Claim = "picture"
	ClaimLocale            Claim = "locale"
	ClaimZoneinfo          Claim = "zoneinfo"
)

// Scope is a single registered OAuth scope.
type Scope struct {
	Name        string
	Description string
	Claims      []Claim
}

// Standard scopes per OIDC Core §5.4.
var standard = []Scope{
	{
		Name:        "openid",
		Description: "Verify who you are.",
		Claims:      []Claim{ClaimSub},
	},
	{
		Name:        "profile",
		Description: "See your basic profile information.",
		Claims:      []Claim{ClaimName, ClaimPreferredUsername, ClaimPicture, ClaimLocale, ClaimZoneinfo},
	},
	{
		Name:        "email",
		Description: "Read your email address.",
		Claims:      []Claim{ClaimEmail, ClaimEmailVerified},
	},
	{
		Name:        "offline_access",
		Description: "Stay signed in when you're not using the app.",
		Claims:      nil,
	},
}

// Catalog provides scope lookup.
type Catalog interface {
	Get(name string) (Scope, bool)
	Describe(name string) string
	ClaimsFor(scopes []string) []Claim
}

// StandardCatalog returns the built-in OIDC catalog.
func StandardCatalog() Catalog { return staticCatalog{} }

type staticCatalog struct{}

func (staticCatalog) Get(name string) (Scope, bool) {
	for _, s := range standard {
		if s.Name == name {
			return s, true
		}
	}
	return Scope{}, false
}

func (c staticCatalog) Describe(name string) string {
	if s, ok := c.Get(name); ok {
		return s.Description
	}
	return name
}

// ClaimsFor returns the union of claims implied by the given scopes,
// preserving registration order and deduplicating.
func (c staticCatalog) ClaimsFor(scopes []string) []Claim {
	seen := map[Claim]struct{}{}
	out := []Claim{}
	for _, sc := range scopes {
		s, ok := c.Get(sc)
		if !ok {
			continue
		}
		for _, cl := range s.Claims {
			if _, ok := seen[cl]; ok {
				continue
			}
			seen[cl] = struct{}{}
			out = append(out, cl)
		}
	}
	return out
}

// Includes reports whether `scopes` includes the literal name `want`.
func Includes(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
