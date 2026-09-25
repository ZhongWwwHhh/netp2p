// Package auth defines the role model that guards every control-plane
// mutation. It mirrors NetBird's role × module × operation matrix so the Web
// console, the admin stream protocol and any future API all agree on who may
// do what.
package auth

import (
	"fmt"
	"sort"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

// Module names a configurable area of the control plane.
type Module string

const (
	ModulePeers       Module = "peers"
	ModuleGroups      Module = "groups"
	ModulePolicies    Module = "policies"
	ModuleRoutes      Module = "routes"
	ModuleDNS         Module = "dns"
	ModuleNameservers Module = "nameservers"
	ModuleSetupKeys   Module = "setup_keys"
	ModuleBudgets     Module = "budgets"
	ModuleSettings    Module = "settings"
	ModuleUsers       Module = "users"
	ModuleEvents      Module = "events"
	ModulePresence    Module = "presence"
	ModulePaths       Module = "paths"
	ModuleDiagnostics Module = "diagnostics"
)

// Operation is what an identity wants to do to a module.
type Operation string

const (
	OpCreate Operation = "create"
	OpRead   Operation = "read"
	OpUpdate Operation = "update"
	OpDelete Operation = "delete"
)

// AllModules lists every module in a stable order, for UI rendering.
var AllModules = []Module{
	ModulePeers,
	ModuleGroups,
	ModulePolicies,
	ModuleRoutes,
	ModuleDNS,
	ModuleNameservers,
	ModuleSetupKeys,
	ModuleBudgets,
	ModuleSettings,
	ModuleUsers,
	ModuleEvents,
	ModulePresence,
	ModulePaths,
	ModuleDiagnostics,
}

// AllOperations lists every operation in a stable order.
var AllOperations = []Operation{OpCreate, OpRead, OpUpdate, OpDelete}

type grant map[Module]map[Operation]bool

func full(modules ...Module) grant {
	result := make(grant, len(modules))
	for _, module := range modules {
		result[module] = map[Operation]bool{
			OpCreate: true, OpRead: true, OpUpdate: true, OpDelete: true,
		}
	}
	return result
}

func readOnly(modules ...Module) grant {
	result := make(grant, len(modules))
	for _, module := range modules {
		result[module] = map[Operation]bool{OpRead: true}
	}
	return result
}

func merge(grants ...grant) grant {
	result := make(grant)
	for _, source := range grants {
		for module, operations := range source {
			if result[module] == nil {
				result[module] = make(map[Operation]bool, len(operations))
			}
			for operation, allowed := range operations {
				if allowed {
					result[module][operation] = true
				}
			}
		}
	}
	return result
}

// configModules are the resources an operator manages through the console.
var configModules = []Module{
	ModulePeers, ModuleGroups, ModulePolicies, ModuleRoutes,
	ModuleDNS, ModuleNameservers, ModuleSetupKeys, ModuleBudgets, ModulePaths,
}

var matrix = map[string]grant{
	model.RoleOwner: merge(
		full(AllModules...),
	),
	model.RoleAdmin: merge(
		full(configModules...),
		readOnly(ModuleSettings, ModuleEvents, ModulePresence, ModuleDiagnostics),
		grant{
			ModuleUsers: {OpRead: true, OpCreate: true, OpUpdate: true},
		},
	),
	model.RoleNetworkAdmin: merge(
		full(configModules...),
		readOnly(ModuleSettings, ModuleUsers, ModuleEvents, ModulePresence, ModuleDiagnostics),
	),
	model.RoleAuditor: merge(
		readOnly(AllModules...),
	),
	model.RoleUsageViewer: merge(
		readOnly(ModuleBudgets, ModuleEvents, ModulePresence),
	),
	model.RoleUser: merge(
		readOnly(ModulePeers, ModuleSettings),
	),
}

// Roles returns every known role in a stable order.
func Roles() []string {
	roles := make([]string, 0, len(matrix))
	for role := range matrix {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	return roles
}

// KnownRole reports whether the role is part of the matrix.
func KnownRole(role string) bool {
	_, ok := matrix[role]
	return ok
}

// Allows is the single source of truth for authorization decisions.
func Allows(role string, module Module, operation Operation) bool {
	grants, ok := matrix[role]
	if !ok {
		return false
	}
	operations, ok := grants[module]
	if !ok {
		return false
	}
	return operations[operation]
}

// Permissions renders the whole matrix for one role, for the session endpoint.
func Permissions(role string) map[Module][]Operation {
	result := make(map[Module][]Operation, len(AllModules))
	for _, module := range AllModules {
		for _, operation := range AllOperations {
			if Allows(role, module, operation) {
				result[module] = append(result[module], operation)
			}
		}
	}
	return result
}

// Identity is an authenticated principal. Role drives authorization; UserID is
// empty for the break-glass static admin token.
type Identity struct {
	Subject string `json:"subject,omitempty"`
	UserID  string `json:"userId,omitempty"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	Role    string `json:"role"`
	// Static marks the break-glass token rather than an SSO-derived identity.
	Static bool `json:"static,omitempty"`
}

// Allows reports whether the identity may perform the operation.
func (identity Identity) Allows(module Module, operation Operation) bool {
	return Allows(identity.Role, module, operation)
}

// BreakGlass is the identity the static admin token maps to: a full owner.
func BreakGlass() Identity {
	return Identity{Role: model.RoleOwner, Name: "static admin token", Static: true}
}

// ActorOf renders an identity as the audit actor attached to a certified
// transition. The static break-glass token has no subject, so it gets a stable
// synthetic id. Actor is evidence only and never affects authorization.
func ActorOf(identity Identity) model.Actor {
	actor := model.Actor{Name: identity.Name, Role: identity.Role, Static: identity.Static}
	switch {
	case identity.Subject != "":
		actor.ID = identity.Subject
	case identity.UserID != "":
		actor.ID = identity.UserID
	case identity.Static:
		actor.ID = "static-admin"
	default:
		actor.ID = "unknown"
	}
	if actor.Name == "" {
		actor.Name = identity.Email
	}
	return actor
}

// PeerActor is the actor recorded for a device that registers itself through
// the login stream. There is no human identity, so the peer id is the subject.
func PeerActor(peerID string) model.Actor {
	return model.Actor{ID: "peer:" + peerID, Name: peerID, Role: "device"}
}

// PermissionError describes an authorization failure without leaking state.
type PermissionError struct {
	Role   string
	Module Module
	Op     Operation
}

func (err *PermissionError) Error() string {
	return fmt.Sprintf("role %q may not %s %s", err.Role, err.Op, err.Module)
}

// AuthorizeTransition maps a transition to the (module, operation) it requires
// and checks the identity against it. The transition types are deliberately
// collapsed onto operations: an upsert needs "update" because the matrix grants
// create and update together everywhere it matters.
func AuthorizeTransition(identity Identity, transitionType string) error {
	module, operation, ok := TransitionPermission(transitionType)
	if !ok {
		return fmt.Errorf("unknown transition type %q", transitionType)
	}
	if !identity.Allows(module, operation) {
		return &PermissionError{Role: identity.Role, Module: module, Op: operation}
	}
	return nil
}

// TransitionPermission maps a transition type to the module and operation it
// needs. Genesis and any unknown type report false.
func TransitionPermission(transitionType string) (Module, Operation, bool) {
	switch transitionType {
	case bft.TransitionRegisterPeer, bft.TransitionUpdatePeer:
		return ModulePeers, OpUpdate, true
	case bft.TransitionUpsertGroup:
		return ModuleGroups, OpUpdate, true
	case bft.TransitionRemoveGroup:
		return ModuleGroups, OpDelete, true
	case bft.TransitionUpsertPolicy:
		return ModulePolicies, OpUpdate, true
	case bft.TransitionRemovePolicy:
		return ModulePolicies, OpDelete, true
	case bft.TransitionUpsertRoute:
		return ModuleRoutes, OpUpdate, true
	case bft.TransitionRemoveRoute:
		return ModuleRoutes, OpDelete, true
	case bft.TransitionUpsertBudget:
		return ModuleBudgets, OpUpdate, true
	case bft.TransitionRemoveBudget:
		return ModuleBudgets, OpDelete, true
	case bft.TransitionUpsertSetupKey:
		return ModuleSetupKeys, OpUpdate, true
	case bft.TransitionRevokeSetupKey:
		return ModuleSetupKeys, OpUpdate, true
	case bft.TransitionRemoveSetupKey:
		return ModuleSetupKeys, OpDelete, true
	case bft.TransitionUpsertNS:
		return ModuleNameservers, OpUpdate, true
	case bft.TransitionRemoveNS:
		return ModuleNameservers, OpDelete, true
	case bft.TransitionUpsertZone, bft.TransitionUpdateDNS:
		return ModuleDNS, OpUpdate, true
	case bft.TransitionRemoveZone:
		return ModuleDNS, OpDelete, true
	case bft.TransitionUpdateSettings:
		return ModuleSettings, OpUpdate, true
	case bft.TransitionRegisterUser:
		return ModuleUsers, OpCreate, true
	case bft.TransitionUpdateUserGroups, bft.TransitionUpdateUserRole, bft.TransitionSetUserBlocked:
		return ModuleUsers, OpUpdate, true
	case bft.TransitionRemoveUser:
		return ModuleUsers, OpDelete, true
	case bft.TransitionUpdateAssignment:
		return ModulePaths, OpUpdate, true
	case bft.TransitionRemoveAssignment:
		return ModulePaths, OpDelete, true
	case bft.TransitionUpdateCommittee, bft.TransitionRotateCommittee:
		return ModuleSettings, OpUpdate, true
	case bft.TransitionUpdateBudgetUse:
		return ModuleBudgets, OpUpdate, true
	}
	return "", "", false
}
