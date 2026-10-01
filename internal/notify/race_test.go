//go:build race

package notify

// The race build tag is set by `go test -race`, which is the only mode the
// ordering test in hub_test.go can fail in: it asserts a happens-before edge, and
// without the detector an unsynchronised read simply returns a value.

func init() {
	raceDetectorEnabled = true
}
