package wire

import (
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

func StateTransitionToProto(transition model.StateTransition) *pb.StateTransition {
	message := &pb.StateTransition{
		Type:        transition.Type,
		SetupKey:    transition.SetupKey,
		RequestId:   transition.RequestID,
		TargetId:    transition.TargetID,
		Committee:   mapSlice(transition.Committee, CommitteeMemberToProto),
		BudgetUsage: BudgetUsageToProto(transition.BudgetUsage),
	}
	// The peer record uses a value type in Go, so an unset peer stays nil.
	if transition.Peer.PeerID != "" {
		message.Peer = PeerRecordToProto(transition.Peer)
	}
	if transition.Group != nil {
		message.Group = GroupToProto(*transition.Group)
	}
	if transition.Policy != nil {
		message.Policy = PolicyToProto(*transition.Policy)
	}
	if transition.Route != nil {
		message.Route = RouteToProto(*transition.Route)
	}
	if transition.Budget != nil {
		message.Budget = TrafficBudgetToProto(*transition.Budget)
	}
	if transition.Record != nil {
		message.SetupKeyRecord = SetupKeyToProto(*transition.Record)
	}
	if transition.Nameserver != nil {
		message.Nameserver = NameserverToProto(*transition.Nameserver)
	}
	if transition.Zone != nil {
		message.Zone = DNSZoneToProto(*transition.Zone)
	}
	if transition.DNSSettings != nil {
		message.DnsSettings = DNSSettingsToProto(*transition.DNSSettings)
	}
	if transition.User != nil {
		message.User = UserToProto(*transition.User)
	}
	if transition.Settings != nil {
		message.Settings = NetworkSettingsToProto(*transition.Settings)
	}
	if transition.Assignment != nil {
		message.Assignment = RouteAssignmentToProto(*transition.Assignment)
	}
	if transition.CommitteeConfig != nil {
		message.CommitteeConfig = CommitteeConfigToProto(*transition.CommitteeConfig)
	}
	if transition.Actor != nil {
		message.Actor = ActorToProto(*transition.Actor)
	}
	return message
}

// ActorToProto and ActorFromProto convert the audit identity. A zero-value
// actor is treated as unset so a nil pointer round-trips cleanly.
func ActorToProto(actor model.Actor) *pb.Actor {
	return &pb.Actor{Id: actor.ID, Name: actor.Name, Role: actor.Role, Static: actor.Static}
}

func ActorFromProto(message *pb.Actor) *model.Actor {
	if message == nil {
		return nil
	}
	return &model.Actor{
		ID: message.GetId(), Name: message.GetName(),
		Role: message.GetRole(), Static: message.GetStatic(),
	}
}

func StateTransitionFromProto(message *pb.StateTransition) model.StateTransition {
	if message == nil {
		return model.StateTransition{}
	}
	transition := model.StateTransition{
		Type:      message.GetType(),
		SetupKey:  message.GetSetupKey(),
		RequestID: message.GetRequestId(),
		TargetID:  message.GetTargetId(),
		Committee: mapSlice(message.GetCommittee(), CommitteeMemberFromProto),
	}
	if message.GetPeer() != nil {
		transition.Peer = PeerRecordFromProto(message.GetPeer())
	}
	if message.GetGroup() != nil {
		group := GroupFromProto(message.GetGroup())
		transition.Group = &group
	}
	if message.GetPolicy() != nil {
		policy := PolicyFromProto(message.GetPolicy())
		transition.Policy = &policy
	}
	if message.GetRoute() != nil {
		route := RouteFromProto(message.GetRoute())
		transition.Route = &route
	}
	if message.GetBudget() != nil {
		budget := TrafficBudgetFromProto(message.GetBudget())
		transition.Budget = &budget
	}
	if message.GetSetupKeyRecord() != nil {
		record := SetupKeyFromProto(message.GetSetupKeyRecord())
		transition.Record = &record
	}
	if message.GetNameserver() != nil {
		nameserver := NameserverFromProto(message.GetNameserver())
		transition.Nameserver = &nameserver
	}
	if message.GetZone() != nil {
		zone := DNSZoneFromProto(message.GetZone())
		transition.Zone = &zone
	}
	if message.GetDnsSettings() != nil {
		settings := DNSSettingsFromProto(message.GetDnsSettings())
		transition.DNSSettings = &settings
	}
	if message.GetUser() != nil {
		user := UserFromProto(message.GetUser())
		transition.User = &user
	}
	if message.GetSettings() != nil {
		settings := NetworkSettingsFromProto(message.GetSettings())
		transition.Settings = &settings
	}
	if message.GetAssignment() != nil {
		assignment := RouteAssignmentFromProto(message.GetAssignment())
		transition.Assignment = &assignment
	}
	if message.GetCommitteeConfig() != nil {
		config := CommitteeConfigFromProto(message.GetCommitteeConfig())
		transition.CommitteeConfig = &config
	}
	if message.GetBudgetUsage() != nil {
		transition.BudgetUsage = BudgetUsageFromProto(message.GetBudgetUsage())
	}
	transition.Actor = ActorFromProto(message.GetActor())
	return transition
}

func BudgetUsageToProto(usage *model.BudgetUsage) *pb.BudgetUsage {
	if usage == nil {
		return nil
	}
	return &pb.BudgetUsage{
		BudgetId:     usage.BudgetID,
		DailyBytes:   usage.DailyBytes,
		MonthlyBytes: usage.MonthlyBytes,
		PeriodDay:    usage.PeriodDay,
		PeriodMonth:  usage.PeriodMonth,
	}
}

func BudgetUsageFromProto(message *pb.BudgetUsage) *model.BudgetUsage {
	if message == nil {
		return nil
	}
	return &model.BudgetUsage{
		BudgetID:     message.GetBudgetId(),
		DailyBytes:   message.GetDailyBytes(),
		MonthlyBytes: message.GetMonthlyBytes(),
		PeriodDay:    message.GetPeriodDay(),
		PeriodMonth:  message.GetPeriodMonth(),
	}
}

func QuorumCertificateToProto(qc model.QuorumCertificate) *pb.QuorumCertificate {
	return &pb.QuorumCertificate{
		Height:             qc.Height,
		Round:              qc.Round,
		StateHash:          cloneBytes(qc.StateHash),
		TransitionHash:     cloneBytes(qc.TransitionHash),
		AggregateSignature: cloneBytes(qc.AggregateSignature),
		SignerBitmap:       cloneBytes(qc.SignerBitmap),
		CommitteeEpoch:     qc.CommitteeEpoch,
		ClientViewHash:     cloneBytes(qc.ClientViewHash),
	}
}

func QuorumCertificateFromProto(message *pb.QuorumCertificate) model.QuorumCertificate {
	if message == nil {
		return model.QuorumCertificate{}
	}
	return model.QuorumCertificate{
		Height:             message.GetHeight(),
		Round:              message.GetRound(),
		StateHash:          cloneBytes(message.GetStateHash()),
		TransitionHash:     cloneBytes(message.GetTransitionHash()),
		AggregateSignature: cloneBytes(message.GetAggregateSignature()),
		SignerBitmap:       cloneBytes(message.GetSignerBitmap()),
		CommitteeEpoch:     message.GetCommitteeEpoch(),
		ClientViewHash:     cloneBytes(message.GetClientViewHash()),
	}
}

func SignedSnapshotToProto(snapshot model.SignedSnapshot) *pb.SignedSnapshot {
	return &pb.SignedSnapshot{
		Epoch:           snapshot.Epoch,
		Height:          snapshot.Height,
		StateHash:       cloneBytes(snapshot.StateHash),
		State:           NetworkStateToProto(snapshot.State),
		Committee:       mapSlice(snapshot.Committee, CommitteeMemberToProto),
		Qc:              QuorumCertificateToProto(snapshot.QC),
		Transition:      StateTransitionToProto(snapshot.Transition),
		LeaderId:        snapshot.LeaderID,
		CommitteeConfig: CommitteeConfigToProto(snapshot.CommitteeConfig),
	}
}

func SignedSnapshotFromProto(message *pb.SignedSnapshot) model.SignedSnapshot {
	if message == nil {
		return model.SignedSnapshot{}
	}
	return model.SignedSnapshot{
		Epoch:           message.GetEpoch(),
		Height:          message.GetHeight(),
		StateHash:       cloneBytes(message.GetStateHash()),
		State:           NetworkStateFromProto(message.GetState()),
		Committee:       mapSlice(message.GetCommittee(), CommitteeMemberFromProto),
		QC:              QuorumCertificateFromProto(message.GetQc()),
		Transition:      StateTransitionFromProto(message.GetTransition()),
		LeaderID:        message.GetLeaderId(),
		CommitteeConfig: CommitteeConfigFromProto(message.GetCommitteeConfig()),
	}
}

func ProposalToProto(proposal model.Proposal) *pb.Proposal {
	return &pb.Proposal{
		Height:     proposal.Height,
		Round:      proposal.Round,
		NetworkId:  proposal.NetworkID,
		State:      NetworkStateToProto(proposal.State),
		LeaderId:   proposal.LeaderID,
		Transition: StateTransitionToProto(proposal.Transition),
	}
}

func ProposalFromProto(message *pb.Proposal) model.Proposal {
	if message == nil {
		return model.Proposal{}
	}
	return model.Proposal{
		Height:     message.GetHeight(),
		Round:      message.GetRound(),
		NetworkID:  message.GetNetworkId(),
		State:      NetworkStateFromProto(message.GetState()),
		LeaderID:   message.GetLeaderId(),
		Transition: StateTransitionFromProto(message.GetTransition()),
	}
}

func CommitteeEnvelopeToProto(envelope model.CommitteeEnvelope) *pb.CommitteeEnvelope {
	result := &pb.CommitteeEnvelope{
		Type:   envelope.Type,
		Height: envelope.Height,
		Round:  envelope.Round,
		Vote:   VoteToProto(envelope.Vote),
	}
	if envelope.Proposal != nil {
		result.Proposal = ProposalToProto(*envelope.Proposal)
	}
	if envelope.Snapshot != nil {
		result.Snapshot = SignedSnapshotToProto(*envelope.Snapshot)
	}
	if envelope.Transition != nil {
		result.Transition = StateTransitionToProto(*envelope.Transition)
	}
	return result
}

func CommitteeEnvelopeFromProto(message *pb.CommitteeEnvelope) model.CommitteeEnvelope {
	if message == nil {
		return model.CommitteeEnvelope{}
	}
	result := model.CommitteeEnvelope{
		Type:   message.GetType(),
		Height: message.GetHeight(),
		Round:  message.GetRound(),
		Vote:   VoteFromProto(message.GetVote()),
	}
	if message.GetProposal() != nil {
		proposal := ProposalFromProto(message.GetProposal())
		result.Proposal = &proposal
	}
	if message.GetSnapshot() != nil {
		snapshot := SignedSnapshotFromProto(message.GetSnapshot())
		result.Snapshot = &snapshot
	}
	if message.GetTransition() != nil {
		transition := StateTransitionFromProto(message.GetTransition())
		result.Transition = &transition
	}
	return result
}

func VoteToProto(vote *model.Vote) *pb.Vote {
	if vote == nil {
		return nil
	}
	return &pb.Vote{
		Height:         vote.Height,
		Round:          vote.Round,
		NetworkId:      vote.NetworkID,
		StateHash:      cloneBytes(vote.StateHash),
		TransitionHash: cloneBytes(vote.TransitionHash),
		VoterId:        vote.VoterID,
		Signature:      cloneBytes(vote.Signature),
		CommitteeEpoch: vote.CommitteeEpoch,
		ClientViewHash: cloneBytes(vote.ClientViewHash),
	}
}

func VoteFromProto(message *pb.Vote) *model.Vote {
	if message == nil {
		return nil
	}
	return &model.Vote{
		Height:         message.GetHeight(),
		Round:          message.GetRound(),
		NetworkID:      message.GetNetworkId(),
		StateHash:      cloneBytes(message.GetStateHash()),
		TransitionHash: cloneBytes(message.GetTransitionHash()),
		VoterID:        message.GetVoterId(),
		Signature:      cloneBytes(message.GetSignature()),
		CommitteeEpoch: message.GetCommitteeEpoch(),
		ClientViewHash: cloneBytes(message.GetClientViewHash()),
	}
}
