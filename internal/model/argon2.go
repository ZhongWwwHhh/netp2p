package model

import "golang.org/x/crypto/argon2"

// Argon2Concurrency bounds expensive password and token derivation across all
// manager authentication paths. Requests queue behind this gate rather than
// exhausting the host with concurrent 64 MiB KDF computations.
const Argon2Concurrency = 2

var argon2Slots = make(chan struct{}, Argon2Concurrency)

// argon2IDKey is the single Argon2 entry point used by NetP2P verifiers. It
// intentionally has no caller-specific bypasses: local login, setup keys, and
// manager enrollment all share the same process-wide CPU budget.
func argon2IDKey(password, salt []byte, iterations, memory uint32, parallelism uint8, keyLength uint32) []byte {
	argon2Slots <- struct{}{}
	defer func() { <-argon2Slots }()
	return argon2.IDKey(password, salt, iterations, memory, parallelism, keyLength)
}
