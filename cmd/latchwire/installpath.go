package main

import "strings"

// insideWindowsDir reports whether the Windows path p is strictly below dir.
// Windows compares names without regard to case and takes either slash. A
// path with a ".." segment is refused rather than resolved.
func insideWindowsDir(p, dir string) bool {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, "/", `\`)) }
	p, dir = norm(p), strings.TrimRight(norm(dir), `\`)
	if dir == "" || !strings.HasPrefix(p, dir+`\`) {
		return false
	}
	for _, seg := range strings.Split(p, `\`) {
		if seg == ".." {
			return false
		}
	}
	return len(p) > len(dir)+1
}
