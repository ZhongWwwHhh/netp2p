package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	hostcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

func TestManagerJoinPreservesSharedRuntimeSecrets(t *testing.T) {
	bundle := config.ManagerJoinBundle{
		AdminToken:    "existing-manager-admin-token-0123456789",
		SessionSecret: "existing-manager-session-secret-0123456",
	}
	if len(bundle.AdminToken) < 32 || len(bundle.SessionSecret) < 32 {
		t.Fatal("test fixture runtime credentials are too short")
	}
}

func TestManagerActivationCompleteAfterLaterTransition(t *testing.T) {
	bundle, members := managerJoinActivationFixture(t)
	snapshot := activatedManagerSnapshot(bundle, members)
	snapshot.Transition = model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "post-activation"},
	}

	if !managerActivationComplete(snapshot, bundle.ManagerID, 2) {
		t.Fatal("activated manager was not recognized after a later certified transition")
	}
	if managerActivationComplete(snapshot, bundle.ManagerID, 1) {
		t.Fatal("stale committee epoch was accepted as activation")
	}
}

func TestManagerActivationCompleteOnActivationHeight(t *testing.T) {
	bundle, members := managerJoinActivationFixture(t)
	snapshot := activatedManagerSnapshot(bundle, members)
	snapshot.Committee = members[:len(members)-1]
	snapshot.CommitteeConfig = model.DefaultCommitteeParams().CommitteeConfig(1, nil)
	newConfig := snapshot.State.CommitteeConfig
	snapshot.Transition = model.StateTransition{
		Type: bft.TransitionActivateCommittee, Committee: members,
		CommitteeConfig: &newConfig,
	}

	if !managerActivationComplete(snapshot, bundle.ManagerID, 2) {
		t.Fatal("activation height used the signing committee instead of the transition committee")
	}
}

func TestPersistActivatedManagerUsesCertifiedCommittee(t *testing.T) {
	bundle, members := managerJoinActivationFixture(t)
	activation := activatedManagerSnapshot(bundle, members)
	activation.Committee = members[:len(members)-1]
	activation.CommitteeConfig = model.DefaultCommitteeParams().CommitteeConfig(1, nil)
	newConfig := activation.State.CommitteeConfig
	activation.Transition = model.StateTransition{
		Type: bft.TransitionActivateCommittee, Committee: members,
		CommitteeConfig: &newConfig,
	}

	manifestPath, managerBundlePath, err := persistActivatedManager(t.TempDir(), bundle, activation)
	if err != nil {
		t.Fatalf("persist activated manager: %v", err)
	}
	manifest, err := config.LoadNetworkManifest(manifestPath)
	if err != nil {
		t.Fatalf("load activated manifest: %v", err)
	}
	if len(manifest.Managers) != 4 || manifest.CommitteeParams != (model.CommitteeParams{Size: 4, FaultLimit: 1, QuorumSize: 3}) {
		t.Fatalf("activated manifest committee = %d %+v", len(manifest.Managers), manifest.CommitteeParams)
	}
	if _, err := config.LoadManagerBundle(managerBundlePath, manifest); err != nil {
		t.Fatalf("load activated manager bundle: %v", err)
	}
}

func managerJoinActivationFixture(t *testing.T) (config.ManagerJoinBundle, []model.CommitteeMember) {
	t.Helper()

	ids := []string{"manager-1", "manager-2", "manager-3", "manager-4"}
	members := make([]model.CommitteeMember, len(ids))
	var candidateKey string
	for index, id := range ids {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		libp2pKey, _, err := hostcrypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peerIDFromKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{
			ID: id, PeerID: peerID,
			Address:           multiaddrForPort(t, 4001+index),
			ListenAddr:        multiaddrForPort(t, 4101+index),
			PublicKey:         publicKey,
			ForwardingEnabled: true,
		}
		if index == len(ids)-1 {
			encoded, err := hostcrypto.MarshalPrivateKey(libp2pKey)
			if err != nil {
				t.Fatal(err)
			}
			candidateKey = base64.StdEncoding.EncodeToString(encoded)
		}
	}
	bundle := config.ManagerJoinBundle{
		Version: config.ManagerJoinBundleVersion, NetworkID: "committee-e2e",
		ManagerID: ids[len(ids)-1], PrivateKey: candidateKey,
		AdminToken:    "0123456789abcdef0123456789abcdef",
		SessionSecret: "0123456789abcdef0123456789abcdef",
		JoinToken:     "0123456789abcdef0123456789abcdef",
		InitDomain:    "manager-1.netp2p.example",
		Address:       members[len(members)-1].Address, QuicListen: members[len(members)-1].Address,
		ListenAddr: members[len(members)-1].ListenAddr, TrustManagers: members[:len(members)-1],
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate manager join bundle: %v", err)
	}
	return bundle, members
}

func activatedManagerSnapshot(bundle config.ManagerJoinBundle, members []model.CommitteeMember) model.SignedSnapshot {
	groupKey := make([]byte, 96)
	for index := range groupKey {
		groupKey[index] = byte(index + 1)
	}
	config := model.CommitteeParams{Size: 4, FaultLimit: 1, QuorumSize: 3}.CommitteeConfig(2, groupKey)
	return model.SignedSnapshot{
		Height: 15, StateHash: make([]byte, 32), Committee: members, CommitteeConfig: config,
		State: model.NetworkState{
			NetworkID: bundle.NetworkID, OverlayCIDR: "100.64.0.0/24",
			CommitteeConfig: config,
			ManagerJoins: []model.ManagerJoinRequest{{
				ID: bundle.ManagerID, ManagerID: bundle.ManagerID,
				Status: model.ManagerJoinActivated,
			}},
		},
	}
}

func peerIDFromKey(key hostcrypto.PrivKey) (string, error) {
	peerID, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return "", err
	}
	return peerID.String(), nil
}

func multiaddrForPort(t *testing.T, port int) string {
	t.Helper()
	address, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/127.0.0.1/udp/%d/quic-v1", port))
	if err != nil {
		t.Fatal(err)
	}
	return address.String()
}
