package wire

import (
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

// ---------------------------------------------------------------------------
// Committee
// ---------------------------------------------------------------------------

func CommitteeMemberToProto(member model.CommitteeMember) *pb.CommitteeMember {
	return &pb.CommitteeMember{
		Id:                member.ID,
		PeerId:            member.PeerID,
		Address:           member.Address,
		KeySeed:           member.KeySeed,
		PublicKey:         cloneBytes(member.PublicKey),
		ListenAddr:        member.ListenAddr,
		ForwardingEnabled: member.ForwardingEnabled,
		BlsPublicKey:      cloneBytes(member.BLSPublicKey),
	}
}

func CommitteeMemberFromProto(message *pb.CommitteeMember) model.CommitteeMember {
	if message == nil {
		return model.CommitteeMember{}
	}
	return model.CommitteeMember{
		ID:                message.GetId(),
		PeerID:            message.GetPeerId(),
		Address:           message.GetAddress(),
		KeySeed:           message.GetKeySeed(),
		PublicKey:         cloneBytes(message.GetPublicKey()),
		ListenAddr:        message.GetListenAddr(),
		ForwardingEnabled: message.GetForwardingEnabled(),
		BLSPublicKey:      cloneBytes(message.GetBlsPublicKey()),
	}
}

func CommitteeConfigToProto(config model.CommitteeConfig) *pb.CommitteeConfig {
	return &pb.CommitteeConfig{
		Threshold:      config.Threshold,
		Size:           config.Size,
		GroupPublicKey: cloneBytes(config.GroupPublicKey),
		CommitteeEpoch: config.CommitteeEpoch,
	}
}

func CommitteeConfigFromProto(message *pb.CommitteeConfig) model.CommitteeConfig {
	if message == nil {
		return model.CommitteeConfig{}
	}
	return model.CommitteeConfig{
		Threshold:      message.GetThreshold(),
		Size:           message.GetSize(),
		GroupPublicKey: cloneBytes(message.GetGroupPublicKey()),
		CommitteeEpoch: message.GetCommitteeEpoch(),
	}
}

// ---------------------------------------------------------------------------
// Peers and settings
// ---------------------------------------------------------------------------

func PeerRecordToProto(peer model.PeerRecord) *pb.PeerRecord {
	return &pb.PeerRecord{
		PeerId:        peer.PeerID,
		OverlayIp:     peer.OverlayIP,
		Addresses:     cloneStrings(peer.Addresses),
		Groups:        cloneStrings(peer.Groups),
		Hostname:      peer.Hostname,
		Os:            peer.OS,
		ClientVersion: peer.ClientVersion,
		UserId:        peer.UserID,
		DnsLabel:      peer.DNSLabel,
		LastLogin:     peer.LastLogin,
		IsExitNode:    peer.IsExitNode,
		Posture:       cloneStrings(peer.Posture),
	}
}

func PeerRecordFromProto(message *pb.PeerRecord) model.PeerRecord {
	if message == nil {
		return model.PeerRecord{}
	}
	return model.PeerRecord{
		PeerID:        message.GetPeerId(),
		OverlayIP:     message.GetOverlayIp(),
		Addresses:     cloneStrings(message.GetAddresses()),
		Groups:        cloneStrings(message.GetGroups()),
		Hostname:      message.GetHostname(),
		OS:            message.GetOs(),
		ClientVersion: message.GetClientVersion(),
		UserID:        message.GetUserId(),
		DNSLabel:      message.GetDnsLabel(),
		LastLogin:     message.GetLastLogin(),
		IsExitNode:    message.GetIsExitNode(),
		Posture:       cloneStrings(message.GetPosture()),
	}
}

func NetworkSettingsToProto(settings model.NetworkSettings) *pb.NetworkSettings {
	return &pb.NetworkSettings{
		DnsDomain:                    settings.DNSDomain,
		LoginExpirationDays:          int32(settings.LoginExpirationDays),
		JwtGroupsEnabled:             settings.JWTGroupsEnabled,
		JwtGroupsClaimName:           settings.JWTGroupsClaimName,
		JwtAllowGroups:               cloneStrings(settings.JWTAllowGroups),
		LinkMinBandwidthMbps:         settings.LinkMinBandwidthMbps,
		ViaManagerLatencyAdvantageMs: settings.ViaManagerLatencyAdvantageMs,
		ViaManagerLossAdvantagePct:   settings.ViaManagerLossAdvantagePct,
		LinkProbeIntervalSeconds:     int32(settings.LinkProbeIntervalSeconds),
		LinkProbeTimeoutMs:           int32(settings.LinkProbeTimeoutMs),
		ViaManagerEnabled:            settings.ViaManagerEnabled,
		DirectPathEnabled:            settings.DirectPathEnabled,
		MaxManagerHops:               int32(settings.MaxManagerHops),
		ProbeBandwidthBudgetKb:       int32(settings.ProbeBandwidthBudgetKB),
		QuotaEnforcementEnabled:      settings.QuotaEnforcementEnabled,
		QuotaReportIntervalSeconds:   int32(settings.QuotaReportIntervalSeconds),
		DefaultFlowClass:             settings.DefaultFlowClass,
		ExitNodeEnabled:              settings.ExitNodeEnabled,
	}
}

func NetworkSettingsFromProto(message *pb.NetworkSettings) model.NetworkSettings {
	if message == nil {
		return model.NetworkSettings{}
	}
	return model.NetworkSettings{
		DNSDomain:                    message.GetDnsDomain(),
		LoginExpirationDays:          int(message.GetLoginExpirationDays()),
		JWTGroupsEnabled:             message.GetJwtGroupsEnabled(),
		JWTGroupsClaimName:           message.GetJwtGroupsClaimName(),
		JWTAllowGroups:               cloneStrings(message.GetJwtAllowGroups()),
		LinkMinBandwidthMbps:         message.GetLinkMinBandwidthMbps(),
		ViaManagerLatencyAdvantageMs: message.GetViaManagerLatencyAdvantageMs(),
		ViaManagerLossAdvantagePct:   message.GetViaManagerLossAdvantagePct(),
		LinkProbeIntervalSeconds:     int(message.GetLinkProbeIntervalSeconds()),
		LinkProbeTimeoutMs:           int(message.GetLinkProbeTimeoutMs()),
		ViaManagerEnabled:            message.GetViaManagerEnabled(),
		DirectPathEnabled:            message.GetDirectPathEnabled(),
		MaxManagerHops:               int(message.GetMaxManagerHops()),
		ProbeBandwidthBudgetKB:       int(message.GetProbeBandwidthBudgetKb()),
		QuotaEnforcementEnabled:      message.GetQuotaEnforcementEnabled(),
		QuotaReportIntervalSeconds:   int(message.GetQuotaReportIntervalSeconds()),
		DefaultFlowClass:             message.GetDefaultFlowClass(),
		ExitNodeEnabled:              message.GetExitNodeEnabled(),
	}
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

func PathSpecToProto(path model.PathSpec) *pb.PathSpec {
	return &pb.PathSpec{
		Id:              path.ID,
		Kind:            string(path.Kind),
		ManagerHops:     cloneStrings(path.ManagerHops),
		RttMilliseconds: path.RTTMilliseconds,
		LossPercent:     path.LossPercent,
		BandwidthMbps:   path.BandwidthMbps,
		Confidence:      path.Confidence,
		Cost:            path.Cost,
	}
}

func PathSpecFromProto(message *pb.PathSpec) model.PathSpec {
	if message == nil {
		return model.PathSpec{}
	}
	return model.PathSpec{
		ID:              message.GetId(),
		Kind:            model.PathKind(message.GetKind()),
		ManagerHops:     cloneStrings(message.GetManagerHops()),
		RTTMilliseconds: message.GetRttMilliseconds(),
		LossPercent:     message.GetLossPercent(),
		BandwidthMbps:   message.GetBandwidthMbps(),
		Confidence:      message.GetConfidence(),
		Cost:            message.GetCost(),
	}
}

func RouteAssignmentToProto(assignment model.RouteAssignment) *pb.RouteAssignment {
	return &pb.RouteAssignment{
		Id:                assignment.ID,
		NetworkId:         assignment.NetworkID,
		SourcePeerId:      assignment.SourcePeerID,
		DestinationPeerId: assignment.DestinationPeerID,
		Epoch:             assignment.Epoch,
		Primary:           PathSpecToProto(assignment.Primary),
		Fallbacks:         mapSlice(assignment.Fallbacks, PathSpecToProto),
		UpdatedAt:         formatTime(assignment.UpdatedAt),
		RequiresAdmission: assignment.RequiresAdmission,
		MaxHops:           int32(assignment.MaxHops),
	}
}

func RouteAssignmentFromProto(message *pb.RouteAssignment) model.RouteAssignment {
	if message == nil {
		return model.RouteAssignment{}
	}
	return model.RouteAssignment{
		ID:                message.GetId(),
		NetworkID:         message.GetNetworkId(),
		SourcePeerID:      message.GetSourcePeerId(),
		DestinationPeerID: message.GetDestinationPeerId(),
		Epoch:             message.GetEpoch(),
		Primary:           PathSpecFromProto(message.GetPrimary()),
		Fallbacks:         mapSlice(message.GetFallbacks(), PathSpecFromProto),
		UpdatedAt:         parseTime(message.GetUpdatedAt()),
		RequiresAdmission: message.GetRequiresAdmission(),
		MaxHops:           int(message.GetMaxHops()),
	}
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

func UserToProto(user model.User) *pb.User {
	return &pb.User{
		Id:                   user.ID,
		Email:                user.Email,
		Name:                 user.Name,
		Role:                 user.Role,
		AutoGroups:           cloneStrings(user.AutoGroups),
		Blocked:              user.Blocked,
		Issued:               user.Issued,
		LastLogin:            user.LastLogin,
		PasswordVerifier:     cloneBytes(user.PasswordVerifier),
		CredentialsChangedAt: user.CredentialsChangedAt,
	}
}

func UserFromProto(message *pb.User) model.User {
	if message == nil {
		return model.User{}
	}
	return model.User{
		ID:                   message.GetId(),
		Email:                message.GetEmail(),
		Name:                 message.GetName(),
		Role:                 message.GetRole(),
		AutoGroups:           cloneStrings(message.GetAutoGroups()),
		Blocked:              message.GetBlocked(),
		Issued:               message.GetIssued(),
		LastLogin:            message.GetLastLogin(),
		PasswordVerifier:     cloneBytes(message.GetPasswordVerifier()),
		CredentialsChangedAt: message.GetCredentialsChangedAt(),
	}
}

func SetupKeyToProto(key model.SetupKey) *pb.SetupKey {
	return &pb.SetupKey{
		Id:          key.ID,
		Name:        key.Name,
		Token:       key.Token,
		TokenPrefix: key.TokenPrefix,
		TokenHash:   cloneBytes(key.TokenHash),
		Type:        key.Type,
		Groups:      cloneStrings(key.Groups),
		ExpiresAt:   key.ExpiresAt,
		UsageLimit:  int32(key.UsageLimit),
		UsedCount:   int32(key.UsedCount),
		Revoked:     key.Revoked,
		CreatedAt:   key.CreatedAt,
		LastUsedAt:  key.LastUsedAt,
	}
}

func SetupKeyFromProto(message *pb.SetupKey) model.SetupKey {
	if message == nil {
		return model.SetupKey{}
	}
	return model.SetupKey{
		ID:          message.GetId(),
		Name:        message.GetName(),
		Token:       message.GetToken(),
		TokenPrefix: message.GetTokenPrefix(),
		TokenHash:   cloneBytes(message.GetTokenHash()),
		Type:        message.GetType(),
		Groups:      cloneStrings(message.GetGroups()),
		ExpiresAt:   message.GetExpiresAt(),
		UsageLimit:  int(message.GetUsageLimit()),
		UsedCount:   int(message.GetUsedCount()),
		Revoked:     message.GetRevoked(),
		CreatedAt:   message.GetCreatedAt(),
		LastUsedAt:  message.GetLastUsedAt(),
	}
}

func GroupToProto(group model.Group) *pb.Group {
	return &pb.Group{
		Id:       group.ID,
		Name:     group.Name,
		UserIds:  cloneStrings(group.UserIDs),
		PeerIds:  cloneStrings(group.PeerIDs),
		Managed:  group.Managed,
		SsoClaim: group.SSOClaim,
		Issued:   group.Issued,
	}
}

func GroupFromProto(message *pb.Group) model.Group {
	if message == nil {
		return model.Group{}
	}
	return model.Group{
		ID:       message.GetId(),
		Name:     message.GetName(),
		UserIDs:  cloneStrings(message.GetUserIds()),
		PeerIDs:  cloneStrings(message.GetPeerIds()),
		Managed:  message.GetManaged(),
		SSOClaim: message.GetSsoClaim(),
		Issued:   message.GetIssued(),
	}
}

// ---------------------------------------------------------------------------
// Access control
// ---------------------------------------------------------------------------

func ServiceToProto(service model.Service) *pb.Service {
	return &pb.Service{Protocol: service.Protocol, StartPort: uint32(service.StartPort), EndPort: uint32(service.EndPort)}
}

func ServiceFromProto(message *pb.Service) model.Service {
	if message == nil {
		return model.Service{}
	}
	return model.Service{
		Protocol:  message.GetProtocol(),
		StartPort: uint16(message.GetStartPort()),
		EndPort:   uint16(message.GetEndPort()),
	}
}

func PolicyToProto(policy model.Policy) *pb.Policy {
	return &pb.Policy{
		Id:                policy.ID,
		SourceGroups:      cloneStrings(policy.SourceGroups),
		DestinationGroups: cloneStrings(policy.DestinationGroups),
		Services:          mapSlice(policy.Services, ServiceToProto),
		Effect:            string(policy.Effect),
		Direction:         string(policy.Direction),
		Posture:           cloneStrings(policy.Posture),
		LinkConstraints:   cloneStrings(policy.LinkConstraints),
		Priority:          int32(policy.Priority),
		FlowClass:         policy.FlowClass,
	}
}

func PolicyFromProto(message *pb.Policy) model.Policy {
	if message == nil {
		return model.Policy{}
	}
	return model.Policy{
		ID:                message.GetId(),
		SourceGroups:      cloneStrings(message.GetSourceGroups()),
		DestinationGroups: cloneStrings(message.GetDestinationGroups()),
		Services:          mapSlice(message.GetServices(), ServiceFromProto),
		Effect:            model.Effect(message.GetEffect()),
		Direction:         model.Direction(message.GetDirection()),
		Posture:           cloneStrings(message.GetPosture()),
		LinkConstraints:   cloneStrings(message.GetLinkConstraints()),
		Priority:          int(message.GetPriority()),
		FlowClass:         message.GetFlowClass(),
	}
}

func RouteToProto(route model.Route) *pb.Route {
	return &pb.Route{
		Id:                 route.ID,
		Destination:        route.Destination,
		RoutingGroup:       route.RoutingGroup,
		DistributionGroups: cloneStrings(route.DistributionGroup),
		Metric:             int32(route.Metric),
		AllowedPathTypes:   cloneStrings(route.AllowedPathTypes),
		MaxHops:            int32(route.MaxHops),
		BudgetIds:          cloneStrings(route.BudgetIDs),
		FlowClass:          route.FlowClass,
		Masquerade:         route.Masquerade,
	}
}

func RouteFromProto(message *pb.Route) model.Route {
	if message == nil {
		return model.Route{}
	}
	return model.Route{
		ID:                message.GetId(),
		Destination:       message.GetDestination(),
		RoutingGroup:      message.GetRoutingGroup(),
		DistributionGroup: cloneStrings(message.GetDistributionGroups()),
		Metric:            int(message.GetMetric()),
		AllowedPathTypes:  cloneStrings(message.GetAllowedPathTypes()),
		MaxHops:           int(message.GetMaxHops()),
		BudgetIDs:         cloneStrings(message.GetBudgetIds()),
		FlowClass:         message.GetFlowClass(),
		Masquerade:        message.GetMasquerade(),
	}
}

func TrafficBudgetToProto(budget model.TrafficBudget) *pb.TrafficBudget {
	return &pb.TrafficBudget{
		Id:                  budget.ID,
		SubjectType:         budget.SubjectType,
		SubjectId:           budget.SubjectID,
		DailyBytes:          budget.DailyBytes,
		MonthlyBytes:        budget.MonthlyBytes,
		PeakBps:             budget.PeakBPS,
		ForwardingCostLimit: budget.ForwardingCostLimit,
		OnExhausted:         budget.OnExhausted,
		UsedDailyBytes:      budget.UsedDailyBytes,
		UsedMonthlyBytes:    budget.UsedMonthlyBytes,
		UpdatedAt:           formatTime(budget.UpdatedAt),
		PeakBurstBytes:      budget.PeakBurstBytes,
	}
}

func TrafficBudgetFromProto(message *pb.TrafficBudget) model.TrafficBudget {
	if message == nil {
		return model.TrafficBudget{}
	}
	return model.TrafficBudget{
		ID:                  message.GetId(),
		SubjectType:         message.GetSubjectType(),
		SubjectID:           message.GetSubjectId(),
		DailyBytes:          message.GetDailyBytes(),
		MonthlyBytes:        message.GetMonthlyBytes(),
		PeakBPS:             message.GetPeakBps(),
		ForwardingCostLimit: message.GetForwardingCostLimit(),
		OnExhausted:         message.GetOnExhausted(),
		UsedDailyBytes:      message.GetUsedDailyBytes(),
		UsedMonthlyBytes:    message.GetUsedMonthlyBytes(),
		UpdatedAt:           parseTime(message.GetUpdatedAt()),
		PeakBurstBytes:      message.GetPeakBurstBytes(),
	}
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

func NameserverToProto(nameserver model.Nameserver) *pb.Nameserver {
	return &pb.Nameserver{
		Id:           nameserver.ID,
		Name:         nameserver.Name,
		Groups:       cloneStrings(nameserver.Groups),
		MatchDomains: cloneStrings(nameserver.MatchDomains),
		Servers:      cloneStrings(nameserver.Servers),
		Primary:      nameserver.Primary,
		Enabled:      nameserver.Enabled,
	}
}

func NameserverFromProto(message *pb.Nameserver) model.Nameserver {
	if message == nil {
		return model.Nameserver{}
	}
	return model.Nameserver{
		ID:           message.GetId(),
		Name:         message.GetName(),
		Groups:       cloneStrings(message.GetGroups()),
		MatchDomains: cloneStrings(message.GetMatchDomains()),
		Servers:      cloneStrings(message.GetServers()),
		Primary:      message.GetPrimary(),
		Enabled:      message.GetEnabled(),
	}
}

func DNSRecordToProto(record model.DNSRecord) *pb.DNSRecord {
	return &pb.DNSRecord{Name: record.Name, Type: record.Type, Value: record.Value, Ttl: int32(record.TTL)}
}

func DNSRecordFromProto(message *pb.DNSRecord) model.DNSRecord {
	if message == nil {
		return model.DNSRecord{}
	}
	return model.DNSRecord{Name: message.GetName(), Type: message.GetType(), Value: message.GetValue(), TTL: int(message.GetTtl())}
}

func DNSZoneToProto(zone model.DNSZone) *pb.DNSZone {
	return &pb.DNSZone{
		Id:      zone.ID,
		Domain:  zone.Domain,
		Records: mapSlice(zone.Records, DNSRecordToProto),
		Groups:  cloneStrings(zone.Groups),
		Enabled: zone.Enabled,
	}
}

func DNSZoneFromProto(message *pb.DNSZone) model.DNSZone {
	if message == nil {
		return model.DNSZone{}
	}
	return model.DNSZone{
		ID:      message.GetId(),
		Domain:  message.GetDomain(),
		Records: mapSlice(message.GetRecords(), DNSRecordFromProto),
		Groups:  cloneStrings(message.GetGroups()),
		Enabled: message.GetEnabled(),
	}
}

func DNSSettingsToProto(settings model.DNSSettings) *pb.DNSSettings {
	return &pb.DNSSettings{Disabled: settings.Disabled, Groups: cloneStrings(settings.Groups)}
}

func DNSSettingsFromProto(message *pb.DNSSettings) model.DNSSettings {
	if message == nil {
		return model.DNSSettings{}
	}
	return model.DNSSettings{Disabled: message.GetDisabled(), Groups: cloneStrings(message.GetGroups())}
}

// ---------------------------------------------------------------------------
// Network state
// ---------------------------------------------------------------------------

func NetworkStateToProto(state model.NetworkState) *pb.NetworkState {
	return &pb.NetworkState{
		NetworkId:       state.NetworkID,
		OverlayCidr:     state.OverlayCIDR,
		Peers:           mapSlice(state.Peers, PeerRecordToProto),
		Users:           mapSlice(state.Users, UserToProto),
		Groups:          mapSlice(state.Groups, GroupToProto),
		Policies:        mapSlice(state.Policies, PolicyToProto),
		Routes:          mapSlice(state.Routes, RouteToProto),
		Budgets:         mapSlice(state.Budgets, TrafficBudgetToProto),
		SetupKeys:       mapSlice(state.SetupKeys, SetupKeyToProto),
		Nameservers:     mapSlice(state.Nameservers, NameserverToProto),
		Zones:           mapSlice(state.Zones, DNSZoneToProto),
		DnsSettings:     DNSSettingsToProto(state.DNSSettings),
		Settings:        NetworkSettingsToProto(state.Settings),
		Assignments:     mapSlice(state.Assignments, RouteAssignmentToProto),
		NextIpOffset:    state.NextIPOffset,
		CommitteeConfig: CommitteeConfigToProto(state.CommitteeConfig),
	}
}

func NetworkStateFromProto(message *pb.NetworkState) model.NetworkState {
	if message == nil {
		return model.NetworkState{}
	}
	return model.NetworkState{
		NetworkID:       message.GetNetworkId(),
		OverlayCIDR:     message.GetOverlayCidr(),
		Peers:           mapSlice(message.GetPeers(), PeerRecordFromProto),
		Users:           mapSlice(message.GetUsers(), UserFromProto),
		Groups:          mapSlice(message.GetGroups(), GroupFromProto),
		Policies:        mapSlice(message.GetPolicies(), PolicyFromProto),
		Routes:          mapSlice(message.GetRoutes(), RouteFromProto),
		Budgets:         mapSlice(message.GetBudgets(), TrafficBudgetFromProto),
		SetupKeys:       mapSlice(message.GetSetupKeys(), SetupKeyFromProto),
		Nameservers:     mapSlice(message.GetNameservers(), NameserverFromProto),
		Zones:           mapSlice(message.GetZones(), DNSZoneFromProto),
		DNSSettings:     DNSSettingsFromProto(message.GetDnsSettings()),
		Settings:        NetworkSettingsFromProto(message.GetSettings()),
		Assignments:     mapSlice(message.GetAssignments(), RouteAssignmentFromProto),
		NextIPOffset:    message.GetNextIpOffset(),
		CommitteeConfig: CommitteeConfigFromProto(message.GetCommitteeConfig()),
	}
}
