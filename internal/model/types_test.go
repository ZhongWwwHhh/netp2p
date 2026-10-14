package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSetupKeyHashUsesArgon2id(t *testing.T) {
	hash := SetupKeyHash("setup-key-secret")
	if len(hash) != 32 {
		t.Fatalf("hash length = %d, want 32", len(hash))
	}
	shaDigest := sha256.Sum256([]byte("setup-key-secret"))
	if bytes.Equal(hash, shaDigest[:]) {
		t.Fatal("setup-key verifier must not be plain SHA-256")
	}
	if !bytes.Equal(hash, SetupKeyHash("setup-key-secret")) {
		t.Fatal("setup-key verifier must be deterministic")
	}
}

func TestPathFamilyNormalizedPreservesManagerHopOrder(t *testing.T) {
	family := PathFamily{ManagerHops: []string{"manager-z", "manager-a", "manager-z"}}
	normalized := family.Normalized()
	if got := strings.Join(normalized.ManagerHops, ","); got != "manager-z,manager-a" {
		t.Fatalf("normalized manager hops = %q; direction and order must be preserved", got)
	}
}

func TestArgon2DerivationIsBounded(t *testing.T) {
	for range Argon2Concurrency {
		select {
		case argon2Slots <- struct{}{}:
		default:
			t.Fatal("argon2 slot unexpectedly unavailable")
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = SetupKeyHash("bounded-argon2-test")
	}()
	select {
	case <-done:
		t.Fatal("Argon2 derivation ran while all global slots were occupied")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-argon2Slots:
	default:
		t.Fatal("expected an occupied Argon2 slot to release")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Argon2 derivation did not finish after a slot was released")
	}
	for {
		select {
		case <-argon2Slots:
		default:
			return
		}
	}
}

func TestPasswordVerifierUsesArgon2id(t *testing.T) {
	verifier := HashPassword("correct horse battery staple")
	if !strings.HasPrefix(string(verifier), "$argon2id$v=19$m=65536,t=1,p=1$") {
		t.Fatalf("verifier = %q, want Argon2id PHC format", verifier)
	}
	if !VerifyPassword("correct horse battery staple", verifier) {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword("incorrect horse battery staple", verifier) {
		t.Fatal("wrong password must not verify")
	}
	if VerifyPassword("password", nil) || VerifyPassword("password", []byte("not-a-verifier")) {
		t.Fatal("malformed verifier must not authenticate")
	}
	if bytes.Equal(HashPassword("same-password"), HashPassword("same-password")) {
		t.Fatal("password verifier salt must be random")
	}
}

func TestClientSnapshotRedactsSecretsAndHashes(t *testing.T) {
	record := SetupKey{
		ID: "key", Token: "setup-key-secret", TokenPrefix: "setup-",
		TokenHash: []byte("verifier"), Groups: []string{"clients"},
	}
	user := User{ID: "user-1", Email: "user@example.com", PasswordVerifier: []byte("password-verifier")}
	snapshot := SignedSnapshot{
		State: NetworkState{
			SetupKeys:            []SetupKey{record},
			Users:                []User{user},
			ManagerJoinTokenHash: []byte("manager-join-verifier"),
			EngineCommittee:      []CommitteeMember{{ID: "engine", KeySeed: 41}},
		},
		Committee: []CommitteeMember{{ID: "committee", KeySeed: 42}},
		Transition: StateTransition{
			SetupKey:             "setup-key-secret",
			ManagerJoinTokenHash: []byte("manager-join-verifier"),
			Record:               &record,
			User:                 &user,
			Committee:            []CommitteeMember{{ID: "transition", KeySeed: 43}},
		},
	}

	client := ClientSnapshot(snapshot)
	encoded, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, forbidden := range []string{
		"setup-key-secret", "setup-", "verifier",
		`"token"`, `"tokenPrefix"`, `"tokenHash"`, `"keySeed"`,
		"password-verifier", `"passwordVerifier"`,
		"manager-join-verifier", `"managerJoinTokenHash"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("client snapshot leaked %q: %s", forbidden, body)
		}
	}
	if snapshot.State.SetupKeys[0].Token == "" ||
		snapshot.State.SetupKeys[0].TokenHash == nil ||
		snapshot.State.Users[0].PasswordVerifier == nil ||
		snapshot.Committee[0].KeySeed == 0 ||
		snapshot.Transition.Record.Token == "" ||
		snapshot.Transition.User.PasswordVerifier == nil {
		t.Fatal("ClientSnapshot mutated the original snapshot")
	}
}
