package main

import "os"

// writeFileMode wraps os.WriteFile so test files can write fixtures
// without re-importing os just for that.
func writeFileMode(path string, body []byte, mode os.FileMode) error {
	return os.WriteFile(path, body, mode)
}
