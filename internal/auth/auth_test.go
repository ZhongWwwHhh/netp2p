package auth

import (
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

func TestOwnerHasEverything(t *testing.T) {
	for _, module := range AllModules {
		for _, operation := range AllOperations {
			if !Allows(model.RoleOwner, module, operation) {
				t.Fatalf("owner must be allowed to %s %s", operation, module)
			}
		}
	}
}

func TestAuditorIsReadOnly(t *testing.T) {
	for _, module := range AllModules {
		if !Allows(model.RoleAuditor, module, OpRead) {
			t.Fatalf("auditor must read %s", module)
		}
		for _, operation := range []Operation{OpCreate, OpUpdate, OpDelete} {
			if Allows(model.RoleAuditor, module, operation) {
				t.Fatalf("auditor must not %s %s", operation, module)
			}
		}
	}
}

func TestUserCanOnlyReadOwnScope(t *testing.T) {
	if !Allows(model.RoleUser, ModulePeers, OpRead) {
		t.Fatal("user must read peers")
	}
	if !Allows(model.RoleUser, ModuleSettings, OpRead) {
		t.Fatal("user must read settings")
	}
	for _, module := range []Module{ModuleGroups, ModulePolicies, ModuleRoutes, ModuleUsers, ModuleSetupKeys} {
		if Allows(model.RoleUser, module, OpRead) {
			t.Fatalf("user must not read %s", module)
		}
	}
	if Allows(model.RoleUser, ModulePeers, OpCreate) {
		t.Fatal("user must not create peers")
	}
}

func TestAdminCannotDeleteUsersOrWriteSettings(t *testing.T) {
	if Allows(model.RoleAdmin, ModuleUsers, OpDelete) {
		t.Fatal("admin must not delete users")
	}
	if !Allows(model.RoleAdmin, ModuleUsers, OpCreate) || !Allows(model.RoleAdmin, ModuleUsers, OpUpdate) {
		t.Fatal("admin must create and update users")
	}
	if Allows(model.RoleAdmin, ModuleSettings, OpUpdate) {
		t.Fatal("admin must not update settings")
	}
	if !Allows(model.RoleAdmin, ModuleSettings, OpRead) {
		t.Fatal("admin must read settings")
	}
}

func TestNetworkAdminHasReadOnlyUsers(t *testing.T) {
	if !Allows(model.RoleNetworkAdmin, ModuleUsers, OpRead) {
		t.Fatal("network_admin must read users")
	}
	if Allows(model.RoleNetworkAdmin, ModuleUsers, OpUpdate) {
		t.Fatal("network_admin must not update users")
	}
	if !Allows(model.RoleNetworkAdmin, ModulePolicies, OpCreate) {
		t.Fatal("network_admin must manage policies")
	}
}

func TestUsageViewerScope(t *testing.T) {
	for _, module := range []Module{ModuleBudgets, ModuleEvents, ModulePresence} {
		if !Allows(model.RoleUsageViewer, module, OpRead) {
			t.Fatalf("usage_viewer must read %s", module)
		}
	}
	if Allows(model.RoleUsageViewer, ModulePolicies, OpRead) {
		t.Fatal("usage_viewer must not read policies")
	}
	if Allows(model.RoleUsageViewer, ModuleBudgets, OpUpdate) {
		t.Fatal("usage_viewer must not update budgets")
	}
}

func TestUnknownRoleAndOperationDenied(t *testing.T) {
	if Allows("billing_admin", ModuleBudgets, OpRead) {
		t.Fatal("unknown role must be denied")
	}
	if Allows(model.RoleOwner, ModulePolicies, "launch") {
		t.Fatal("unknown operation must be denied")
	}
}

func TestTransitionPermissionMapping(t *testing.T) {
	cases := []struct {
		transitionType string
		module         Module
		operation      Operation
	}{
		{bft.TransitionUpsertPolicy, ModulePolicies, OpUpdate},
		{bft.TransitionRemovePolicy, ModulePolicies, OpDelete},
		{bft.TransitionUpsertGroup, ModuleGroups, OpUpdate},
		{bft.TransitionRemoveGroup, ModuleGroups, OpDelete},
		{bft.TransitionUpsertRoute, ModuleRoutes, OpUpdate},
		{bft.TransitionUpsertBudget, ModuleBudgets, OpUpdate},
		{bft.TransitionUpsertSetupKey, ModuleSetupKeys, OpUpdate},
		{bft.TransitionUpsertNS, ModuleNameservers, OpUpdate},
		{bft.TransitionUpsertZone, ModuleDNS, OpUpdate},
		{bft.TransitionUpdateDNS, ModuleDNS, OpUpdate},
		{bft.TransitionRemoveZone, ModuleDNS, OpDelete},
		{bft.TransitionUpdateSettings, ModuleSettings, OpUpdate},
		{bft.TransitionRequestCommitteeShrink, ModuleSettings, OpUpdate},
		{bft.TransitionRegisterUser, ModuleUsers, OpCreate},
		{bft.TransitionUpdateUserRole, ModuleUsers, OpUpdate},
		{bft.TransitionRemoveUser, ModuleUsers, OpDelete},
		{bft.TransitionRegisterPeer, ModulePeers, OpUpdate},
	}
	for _, testCase := range cases {
		module, operation, ok := TransitionPermission(testCase.transitionType)
		if !ok {
			t.Fatalf("%s: no mapping", testCase.transitionType)
		}
		if module != testCase.module || operation != testCase.operation {
			t.Fatalf("%s: got (%s,%s), want (%s,%s)", testCase.transitionType, module, operation, testCase.module, testCase.operation)
		}
	}
	if _, _, ok := TransitionPermission(bft.TransitionGenesis); ok {
		t.Fatal("genesis must not be submittable through the admin plane")
	}
}

func TestAuthorizeTransitionRejectsUserRole(t *testing.T) {
	identity := Identity{Role: model.RoleUser}
	if err := AuthorizeTransition(identity, bft.TransitionUpsertPolicy); err == nil {
		t.Fatal("a user must not create policies")
	}
	if err := AuthorizeTransition(Identity{Role: model.RoleOwner}, bft.TransitionUpsertPolicy); err != nil {
		t.Fatalf("owner should be allowed: %v", err)
	}
}

func TestPermissionsRenderCoversEveryModule(t *testing.T) {
	permissions := Permissions(model.RoleAuditor)
	if len(permissions) != len(AllModules) {
		t.Fatalf("permissions cover %d modules, want %d", len(permissions), len(AllModules))
	}
}
