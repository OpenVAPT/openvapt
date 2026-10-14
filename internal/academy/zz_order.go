package academy

import (
	"sort"
	"strconv"
)

// levelRank orders the levels as they are taught.
var levelRank = map[Level]int{Foundation: 0, Practitioner: 1, Applied: 2}

// moduleLess orders modules by level (Foundations, Practitioner, Applied) and
// then by the number in their id (P2 before P10).
func moduleLess(a, b Module) bool {
	if ra, rb := levelRank[a.Level], levelRank[b.Level]; ra != rb {
		return ra < rb
	}
	return moduleNumber(a.ID) < moduleNumber(b.ID)
}

// moduleNumber returns the numeric part of an id such as "P15"; an id with no
// number sorts after the numbered ones.
func moduleNumber(id string) int {
	for i := 0; i < len(id); i++ {
		if id[i] >= '0' && id[i] <= '9' {
			n, err := strconv.Atoi(id[i:])
			if err != nil {
				return 1 << 30
			}
			return n
		}
	}
	return 1 << 30
}

// Modules is assembled by several files, each appending its own modules in
// init. Go runs a package's init functions in the order of the file names
// given to the compiler, which the go tool sorts, so this file (zz_) runs last
// and puts the whole course into teaching order once, before anything reads
// it. The website, the "learn" command and the worksheets all read Modules
// after this, so the order is identical everywhere.
func init() {
	sort.SliceStable(Modules, func(i, j int) bool { return moduleLess(Modules[i], Modules[j]) })
}
