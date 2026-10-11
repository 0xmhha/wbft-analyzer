package privacy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
)

var (
	chapterFile = regexp.MustCompile(`^[AB]-\d{2}-.*\.md$`)
	reqLine     = regexp.MustCompile(`^\[((?:WBFT|SNET)-[A-Z]+-\d{3})\]`)
)

// Extract returns the requirement IDs defined in the chapter files
// (A-NN-*.md, B-NN-*.md) of a specification directory, sorted: the lines
// that start with "[ID]", as wbft-inspector reads them. An ID defined twice
// is an error.
func Extract(specDir string) ([]string, error) {
	entries, err := os.ReadDir(specDir)
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !chapterFile.MatchString(e.Name()) {
			continue
		}
		f, err := os.Open(filepath.Join(specDir, e.Name()))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			m := reqLine.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			if prev, dup := seen[m[1]]; dup {
				_ = f.Close()
				return nil, fmt.Errorf("privacy: %s is defined in %s and %s", m[1], prev, e.Name())
			}
			seen[m[1]] = e.Name()
			out = append(out, m[1])
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(out)
	return out, nil
}
