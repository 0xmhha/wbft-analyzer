package privacy

import (
	"errors"
	"regexp"
	"slices"
	"sync"
)

// Extension adds a trusted inspector profile at initialization time. Added
// profiles always require private storage, including their public results.
// Registering code belongs in an operator-owned package included by an overlay.
type Extension struct {
	Build        string
	Requirements []string
	Catalogs     []string
}

type profile struct{ requirements, catalogs map[string]bool }
type registry struct {
	mu       sync.Mutex
	frozen   bool
	profiles map[string]profile
}

var extensions registry
var buildRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func (r *registry) register(e Extension) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return errors.New("privacy: registration is closed")
	}
	if !buildRe.MatchString(e.Build) || e.Build == "public" || len(e.Requirements) == 0 || len(e.Catalogs) == 0 {
		return errors.New("privacy: invalid private profile")
	}
	if _, ok := r.profiles[e.Build]; ok {
		return errors.New("privacy: duplicate private profile")
	}
	p := profile{requirements: map[string]bool{}, catalogs: map[string]bool{}}
	for _, id := range e.Requirements {
		if !idRe.MatchString(id) || p.requirements[id] {
			return errors.New("privacy: invalid private requirement set")
		}
		p.requirements[id] = true
	}
	for _, hash := range e.Catalogs {
		if !catalogRe.MatchString(hash) || p.catalogs[hash] {
			return errors.New("privacy: invalid private catalog set")
		}
		p.catalogs[hash] = true
	}
	if r.profiles == nil {
		r.profiles = map[string]profile{}
	}
	r.profiles[e.Build] = p
	return nil
}

// RegisterExtension copies a complete private trust profile. No environment
// variable, runtime configuration, or request can register trust in a stock build.
func RegisterExtension(e Extension) error { return extensions.register(e) }

func (r *registry) private() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frozen = true
	return len(r.profiles) > 0
}

// Visibility is the deployment and newly created dataset classification.
// Once consulted the registry cannot be extended further.
func Visibility() string {
	if extensions.private() {
		return "private"
	}
	return "public"
}

// TrustedBuild checks the report's exact inspector profile. Extensions cannot
// change the built-in public profile or add trust to its catalog.
func TrustedBuild(build string) bool {
	_ = Visibility()
	if build == "public" {
		return true
	}
	extensions.mu.Lock()
	defer extensions.mu.Unlock()
	extensions.frozen = true
	_, ok := extensions.profiles[build]
	return ok
}

// TrustedRequirement checks only the selected build's requirement set.
func TrustedRequirement(build, id string) bool {
	_ = Visibility()
	if build == "public" {
		return PublicRequirement(id)
	}
	extensions.mu.Lock()
	defer extensions.mu.Unlock()
	extensions.frozen = true
	return extensions.profiles[build].requirements[id]
}

// TrustedCatalog checks only the selected build's complete catalog hash.
func TrustedCatalog(build, hash string) bool {
	_ = Visibility()
	if build == "public" {
		_, ok := PublicCatalog(hash)
		return ok
	}
	extensions.mu.Lock()
	defer extensions.mu.Unlock()
	extensions.frozen = true
	return extensions.profiles[build].catalogs[hash]
}

// PublicRequirements returns a copy for an initialization-time overlay to use
// when assembling its complete private profile.
func PublicRequirements() []string {
	once.Do(load)
	out := make([]string, 0, len(requirements))
	for id := range requirements {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
