// Package privacy holds what the public analyzer build knows to be public:
// the requirement IDs of the public specification (pinned by spec.lock)
// and the catalog hashes of public inspector builds. A report that names
// anything else is refused as a whole (design.md 9, 3).
package privacy

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed data/requirements.txt
var requirementsTxt string

//go:embed data/inspector-catalogs.txt
var catalogsTxt string

// idRe is the form of a requirement ID.
var idRe = regexp.MustCompile(`^(WBFT|SNET)-[A-Z]+-[0-9]{3}$`)

// catalogRe is the form of a catalog hash (sha256, lower-case hex).
var catalogRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	once         sync.Once
	requirements map[string]bool
	catalogs     map[string]string // hash -> inspector commit
	loadErr      error
)

func load() {
	requirements, catalogs = map[string]bool{}, map[string]string{}
	for i, l := range lines(requirementsTxt) {
		if !idRe.MatchString(l) {
			loadErr = fmt.Errorf("privacy: requirements.txt line %d: %q is not a requirement ID", i+1, l)
			return
		}
		requirements[l] = true
	}
	for i, l := range lines(catalogsTxt) {
		f := strings.Fields(l)
		if len(f) != 2 || !catalogRe.MatchString(f[0]) {
			loadErr = fmt.Errorf("privacy: inspector-catalogs.txt line %d: want \"<sha256> <inspector commit>\"", i+1)
			return
		}
		catalogs[f[0]] = f[1]
	}
}

// lines returns the lines of s that are neither empty nor comments, with
// their numbers counted among those lines only.
func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// Check reports an error in the embedded lists.
func Check() error {
	_ = Visibility()
	once.Do(load)
	return loadErr
}

// PublicRequirement reports whether id is a requirement of the public
// specification.
func PublicRequirement(id string) bool {
	once.Do(load)
	return requirements[id]
}

// Requirements returns the number of public requirements.
func Requirements() int {
	once.Do(load)
	return len(requirements)
}

// PublicCatalog reports whether hash is the catalog hash of a public
// inspector build, and the inspector commit it was taken from.
func PublicCatalog(hash string) (commit string, ok bool) {
	once.Do(load)
	commit, ok = catalogs[hash]
	return commit, ok
}
