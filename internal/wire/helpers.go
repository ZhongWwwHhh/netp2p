package wire

// cloneBytes returns an independent copy so callers cannot alias protobuf
// buffers that may be reused by the runtime.
func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

// cloneStrings copies a slice, preserving nil so empty and unset stay
// distinguishable where the domain model cares.
func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

// mapSlice converts every element of a slice. An empty input yields nil so the
// protobuf field stays unset and marshals to nothing.
func mapSlice[In any, Out any](values []In, convert func(In) Out) []Out {
	if len(values) == 0 {
		return nil
	}
	result := make([]Out, 0, len(values))
	for _, value := range values {
		result = append(result, convert(value))
	}
	return result
}
