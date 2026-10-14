package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

type adminCredentialOptions struct {
	email        string
	newEmail     string
	passwordFile string
}

type managerJoinTokenUpdate struct {
	Token string `json:"token"`
}

func runAdmin(ctx context.Context, managerAddr, token, action, file, target string, credentials adminCredentialOptions) error {
	info, err := peer.AddrInfoFromString(managerAddr)
	if err != nil {
		return fmt.Errorf("invalid manager address: %w", err)
	}
	node, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	if err != nil {
		return err
	}
	defer node.Close()
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := node.Host.Connect(connectCtx, *info); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	if payload, ok, err := runAdminQuery(ctx, node, info.ID, token, action); err != nil {
		return err
	} else if ok {
		fmt.Println(string(payload))
		return nil
	}
	var transition model.StateTransition
	var buildErr error
	switch action {
	case "update-user-credentials":
		transition, buildErr = buildAdminCredentialsTransition(ctx, node, info.ID, token, target, credentials)
	case "approve-manager-join", "reject-manager-join":
		status := model.ManagerJoinApproved
		if action == "reject-manager-join" {
			status = model.ManagerJoinRejected
		}
		transition, buildErr = buildManagerJoinReviewTransition(ctx, node, info.ID, token, target, status)
	default:
		transition, buildErr = buildTransition(action, file, target)
	}
	if buildErr != nil {
		return buildErr
	}
	adminCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	snapshot, err := manager.SubmitAdmin(adminCtx, node, info.ID, token, transition)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(map[string]any{
		"height":    snapshot.Height,
		"action":    action,
		"stateHash": fmt.Sprintf("%x", snapshot.StateHash),
	}, "", "  ")
	fmt.Println(string(encoded))
	return nil
}

func buildAdminCredentialsTransition(
	ctx context.Context, node *p2p.Node, managerID peer.ID, token, targetID string,
	options adminCredentialOptions,
) (model.StateTransition, error) {
	transition := model.StateTransition{Type: bft.TransitionUpdateUserCredentials}
	var directory model.SignedSnapshot
	if targetID == "" {
		email := strings.ToLower(strings.TrimSpace(options.email))
		if email == "" {
			return transition, fmt.Errorf("--email or --target is required")
		}
		queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		payload, err := manager.QueryAdmin(queryCtx, node, managerID, token, "snapshot")
		if err != nil {
			return transition, fmt.Errorf("query user directory: %w", err)
		}
		if err := json.Unmarshal(payload, &directory); err != nil {
			return transition, fmt.Errorf("decode snapshot: %w", err)
		}
		for _, user := range directory.State.Users {
			if strings.EqualFold(user.Email, email) {
				targetID = user.ID
				break
			}
		}
		if targetID == "" {
			return transition, fmt.Errorf("user %q not found", email)
		}
	}
	update := model.User{ID: targetID}
	if newEmail := strings.ToLower(strings.TrimSpace(options.newEmail)); newEmail != "" {
		update.Email = newEmail
	}
	if options.passwordFile != "" {
		password, err := os.ReadFile(options.passwordFile)
		if err != nil {
			return transition, fmt.Errorf("read password file: %w", err)
		}
		password = []byte(strings.TrimRight(string(password), "\r\n"))
		if len(password) < 12 {
			return transition, fmt.Errorf("password file must contain at least 12 characters")
		}
		update.PasswordVerifier = model.HashPassword(string(password))
	}
	if update.Email == "" && update.PasswordVerifier == nil {
		return transition, fmt.Errorf("--new-email or --password-file is required")
	}
	if update.PasswordVerifier == nil {
		// Email-only changes are a certified credential update, but they keep
		// the existing password. Fetch the verifier from the manager-only
		// snapshot so clients never need to submit or store a password.
		if len(directory.State.Users) == 0 {
			queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			payload, err := manager.QueryAdmin(queryCtx, node, managerID, token, "snapshot")
			cancel()
			if err != nil {
				return transition, fmt.Errorf("query user directory: %w", err)
			}
			if err := json.Unmarshal(payload, &directory); err != nil {
				return transition, fmt.Errorf("decode snapshot: %w", err)
			}
		}
		current := findDirectoryUser(directory, targetID)
		if current == nil || len(current.PasswordVerifier) == 0 {
			return transition, fmt.Errorf("existing password verifier not found for user %q", targetID)
		}
		update.PasswordVerifier = current.PasswordVerifier
	}
	update.CredentialsChangedAt = time.Now().UTC().Format(time.RFC3339Nano)
	transition.TargetID = targetID
	transition.User = &update
	return transition, nil
}

func findDirectoryUser(snapshot model.SignedSnapshot, userID string) *model.User {
	for index := range snapshot.State.Users {
		if snapshot.State.Users[index].ID == userID {
			return &snapshot.State.Users[index]
		}
	}
	return nil
}

func buildManagerJoinReviewTransition(
	ctx context.Context, node *p2p.Node, managerID peer.ID, token, targetID string,
	status model.ManagerJoinStatus,
) (model.StateTransition, error) {
	transition := model.StateTransition{Type: bft.TransitionReviewManagerJoin}
	if targetID == "" {
		return transition, fmt.Errorf("--target is required for manager join review")
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	payload, err := manager.QueryAdmin(queryCtx, node, managerID, token, "snapshot")
	if err != nil {
		return transition, fmt.Errorf("query manager join queue: %w", err)
	}
	var snapshot model.SignedSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return transition, fmt.Errorf("decode manager join queue: %w", err)
	}
	return managerJoinReviewTransition(snapshot, targetID, status, "static admin token", time.Now().UTC())
}

func managerJoinReviewTransition(
	snapshot model.SignedSnapshot, targetID string, status model.ManagerJoinStatus,
	reviewedBy string, reviewedAt time.Time,
) (model.StateTransition, error) {
	transition := model.StateTransition{Type: bft.TransitionReviewManagerJoin}
	if status != model.ManagerJoinApproved && status != model.ManagerJoinRejected {
		return transition, fmt.Errorf("invalid manager join review status %q", status)
	}
	if reviewedBy == "" || reviewedAt.IsZero() {
		return transition, fmt.Errorf("manager join reviewer and review time are required")
	}
	for index := range snapshot.State.ManagerJoins {
		request := snapshot.State.ManagerJoins[index]
		if request.ManagerID != targetID && request.ID != targetID {
			continue
		}
		if request.Status != model.ManagerJoinPending {
			return transition, fmt.Errorf("manager join request %q is %s, not pending", request.ID, request.Status)
		}
		request.Status = status
		request.ReviewedBy = reviewedBy
		request.ReviewedAt = reviewedAt.UTC().Format(time.RFC3339Nano)
		if status == model.ManagerJoinRejected && request.Reason == "" {
			request.Reason = "Rejected by administrator"
		}
		transition.ManagerJoin = &request
		return transition, nil
	}
	return transition, fmt.Errorf("pending manager join request %q not found", targetID)
}

// adminQueries maps read-only CLI actions to admin protocol queries.
var adminQueries = map[string]string{
	"show-snapshot": "snapshot",
}

func runAdminQuery(ctx context.Context, node *p2p.Node, managerID peer.ID, token, action string) ([]byte, bool, error) {
	query, ok := adminQueries[action]
	if !ok {
		return nil, false, nil
	}
	queryCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	payload, err := manager.QueryAdmin(queryCtx, node, managerID, token, query)
	if err != nil {
		return nil, true, err
	}
	return payload, true, nil
}

func buildTransition(action, file, target string) (model.StateTransition, error) {
	transition := model.StateTransition{}
	switch action {
	case "upsert-group":
		transition.Type = bft.TransitionUpsertGroup
		var group model.Group
		if err := loadRecord(file, &group); err != nil {
			return transition, err
		}
		transition.Group = &group
	case "remove-group":
		transition.Type = bft.TransitionRemoveGroup
		transition.TargetID = target
	case "upsert-policy":
		transition.Type = bft.TransitionUpsertPolicy
		var policy model.Policy
		if err := loadRecord(file, &policy); err != nil {
			return transition, err
		}
		transition.Policy = &policy
	case "remove-policy":
		transition.Type = bft.TransitionRemovePolicy
		transition.TargetID = target
	case "update-peer":
		transition.Type = bft.TransitionUpdatePeer
		var peer model.PeerRecord
		if err := loadRecord(file, &peer); err != nil {
			return transition, err
		}
		transition.Peer = peer
	case "upsert-route":
		transition.Type = bft.TransitionUpsertRoute
		var route model.Route
		if err := loadRecord(file, &route); err != nil {
			return transition, err
		}
		transition.Route = &route
	case "remove-route":
		transition.Type = bft.TransitionRemoveRoute
		transition.TargetID = target
	case "upsert-budget":
		transition.Type = bft.TransitionUpsertBudget
		var budget model.TrafficBudget
		if err := loadRecord(file, &budget); err != nil {
			return transition, err
		}
		transition.Budget = &budget
	case "remove-budget":
		transition.Type = bft.TransitionRemoveBudget
		transition.TargetID = target
	case "upsert-setup-key":
		transition.Type = bft.TransitionUpsertSetupKey
		var record model.SetupKey
		if err := loadRecord(file, &record); err != nil {
			return transition, err
		}
		if err := normalizeSetupKey(&record); err != nil {
			return transition, err
		}
		transition.Record = &record
	case "remove-setup-key":
		transition.Type = bft.TransitionRemoveSetupKey
		transition.TargetID = target
	case "upsert-nameserver":
		transition.Type = bft.TransitionUpsertNS
		var nameserver model.Nameserver
		if err := loadRecord(file, &nameserver); err != nil {
			return transition, err
		}
		transition.Nameserver = &nameserver
	case "remove-nameserver":
		transition.Type = bft.TransitionRemoveNS
		transition.TargetID = target
	case "upsert-zone":
		transition.Type = bft.TransitionUpsertZone
		var zone model.DNSZone
		if err := loadRecord(file, &zone); err != nil {
			return transition, err
		}
		transition.Zone = &zone
	case "remove-zone":
		transition.Type = bft.TransitionRemoveZone
		transition.TargetID = target
	case "update-dns-settings":
		transition.Type = bft.TransitionUpdateDNS
		var settings model.DNSSettings
		if err := loadRecord(file, &settings); err != nil {
			return transition, err
		}
		transition.DNSSettings = &settings
	case "update-settings":
		transition.Type = bft.TransitionUpdateSettings
		var settings model.NetworkSettings
		if err := loadRecord(file, &settings); err != nil {
			return transition, err
		}
		transition.Settings = &settings
	case "update-committee":
		transition.Type = bft.TransitionUpdateCommittee
		var committee []model.CommitteeMember
		if err := loadRecord(file, &committee); err != nil {
			return transition, err
		}
		transition.Committee = committee
	case "request-committee-shrink":
		transition.Type = bft.TransitionRequestCommitteeShrink
		var committee []model.CommitteeMember
		if err := loadRecord(file, &committee); err != nil {
			return transition, err
		}
		transition.Committee = committee
	case "rotate-committee-keys":
		transition.Type = bft.TransitionRotateCommittee
	case "rotate-manager-join-token":
		transition.Type = bft.TransitionRotateManagerJoinToken
		var update managerJoinTokenUpdate
		if err := loadRecord(file, &update); err != nil {
			return transition, err
		}
		token := strings.TrimSpace(update.Token)
		if len(token) < 32 {
			return transition, fmt.Errorf("manager join token must be at least 32 bytes")
		}
		transition.ManagerJoinTokenHash = model.ManagerJoinTokenHash(token)
	default:
		return transition, fmt.Errorf("unknown action %q", action)
	}
	if action != "rotate-committee-keys" && transition.TargetID == "" && file == "" {
		return transition, fmt.Errorf("--file or --target is required for action %q", action)
	}
	return transition, nil
}

func normalizeSetupKey(record *model.SetupKey) error {
	token := strings.TrimSpace(record.Token)
	if token == "" && len(record.TokenHash) == 0 {
		return fmt.Errorf("setup key requires token or tokenHash")
	}
	record.Token = ""
	if token != "" {
		record.TokenHash = model.SetupKeyHash(token)
	}
	return nil
}

func loadRecord(path string, value any) error {
	if path == "" {
		return fmt.Errorf("--file is required for this action")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read record file: %w", err)
	}
	return json.Unmarshal(data, value)
}
