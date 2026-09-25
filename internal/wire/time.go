// Package wire converts between the Go domain model and the protobuf wire
// schema. Protobuf only exists at the transport and hashing boundary: the rest
// of the code keeps working with plain Go structs.
package wire

import "time"

// formatTime renders a timestamp as RFC3339Nano. The zero time becomes an empty
// string so the encoding is stable and omits meaningless values.
func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

// parseTime is the inverse of formatTime. Malformed input yields the zero time
// rather than an error: timestamps in observations are advisory, and callers
// that need strictness validate the semantic value separately.
func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
