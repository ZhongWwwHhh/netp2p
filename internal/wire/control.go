package wire

import (
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

func LoginRequestToProto(request protocol.LoginRequest) *pb.LoginRequest {
	return &pb.LoginRequest{
		NetworkId:       request.NetworkID,
		SetupKey:        request.SetupKey,
		JwtToken:        request.JWTToken,
		PeerId:          request.PeerID,
		Addresses:       cloneStrings(request.Addresses),
		Hostname:        request.Hostname,
		Os:              request.OS,
		ClientVersion:   request.ClientVersion,
		ProtocolVersion: request.ProtocolVersion,
		Capabilities:    cloneStrings(request.Capabilities),
		Posture:         cloneStrings(request.Posture),
	}
}

func LoginRequestFromProto(message *pb.LoginRequest) protocol.LoginRequest {
	if message == nil {
		return protocol.LoginRequest{}
	}
	return protocol.LoginRequest{
		NetworkID:       message.GetNetworkId(),
		SetupKey:        message.GetSetupKey(),
		JWTToken:        message.GetJwtToken(),
		PeerID:          message.GetPeerId(),
		Addresses:       cloneStrings(message.GetAddresses()),
		Hostname:        message.GetHostname(),
		OS:              message.GetOs(),
		ClientVersion:   message.GetClientVersion(),
		ProtocolVersion: message.GetProtocolVersion(),
		Capabilities:    cloneStrings(message.GetCapabilities()),
		Posture:         cloneStrings(message.GetPosture()),
	}
}

func LoginResponseToProto(response protocol.LoginResponse) *pb.LoginResponse {
	return &pb.LoginResponse{
		Snapshot:        SignedSnapshotToProto(response.Snapshot),
		Peer:            PeerRecordToProto(response.Peer),
		Error:           response.Error,
		Code:            response.Code,
		ProtocolVersion: response.ProtocolVersion,
		Capabilities:    cloneStrings(response.Capabilities),
	}
}

func LoginResponseFromProto(message *pb.LoginResponse) protocol.LoginResponse {
	if message == nil {
		return protocol.LoginResponse{}
	}
	return protocol.LoginResponse{
		Snapshot:        SignedSnapshotFromProto(message.GetSnapshot()),
		Peer:            PeerRecordFromProto(message.GetPeer()),
		Error:           message.GetError(),
		Code:            message.GetCode(),
		ProtocolVersion: message.GetProtocolVersion(),
		Capabilities:    cloneStrings(message.GetCapabilities()),
	}
}

func SyncRequestToProto(request protocol.SyncRequest) *pb.SyncRequest {
	return &pb.SyncRequest{
		NetworkId:         request.NetworkID,
		PeerId:            request.PeerID,
		Height:            request.Height,
		AssignmentsHeight: request.AssignmentsHeight,
		Admissions:        mapSlice(request.Admissions, AdmissionReportToProto),
		ProtocolVersion:   request.ProtocolVersion,
	}
}

func SyncRequestFromProto(message *pb.SyncRequest) protocol.SyncRequest {
	if message == nil {
		return protocol.SyncRequest{}
	}
	return protocol.SyncRequest{
		NetworkID:         message.GetNetworkId(),
		PeerID:            message.GetPeerId(),
		Height:            message.GetHeight(),
		AssignmentsHeight: message.GetAssignmentsHeight(),
		Admissions:        mapSlice(message.GetAdmissions(), AdmissionReportFromProto),
		ProtocolVersion:   message.GetProtocolVersion(),
	}
}

func AdmissionReportToProto(report protocol.AdmissionReport) *pb.AdmissionReport {
	return &pb.AdmissionReport{
		AssignmentId: report.AssignmentID,
		PathId:       report.PathID,
		Ok:           report.OK,
		RttMs:        report.RTTMs,
		LossPct:      report.LossPct,
		ObservedAt:   formatTime(report.ObservedAt),
	}
}

func AdmissionReportFromProto(message *pb.AdmissionReport) protocol.AdmissionReport {
	if message == nil {
		return protocol.AdmissionReport{}
	}
	return protocol.AdmissionReport{
		AssignmentID: message.GetAssignmentId(),
		PathID:       message.GetPathId(),
		OK:           message.GetOk(),
		RTTMs:        message.GetRttMs(),
		LossPct:      message.GetLossPct(),
		ObservedAt:   parseTime(message.GetObservedAt()),
	}
}

func AdminRequestToProto(token string, transition model.StateTransition) *pb.AdminRequest {
	return &pb.AdminRequest{Token: token, Transition: StateTransitionToProto(transition)}
}

func AdminRequestFromProto(message *pb.AdminRequest) (string, model.StateTransition) {
	if message == nil {
		return "", model.StateTransition{}
	}
	return message.GetToken(), StateTransitionFromProto(message.GetTransition())
}

func AdminResponseToProto(snapshot *model.SignedSnapshot, errMessage string) *pb.AdminResponse {
	response := &pb.AdminResponse{Error: errMessage}
	if snapshot != nil {
		response.Snapshot = SignedSnapshotToProto(*snapshot)
	}
	return response
}

func AdminResponseFromProto(message *pb.AdminResponse) (*model.SignedSnapshot, string) {
	if message == nil {
		return nil, ""
	}
	var snapshot *model.SignedSnapshot
	if message.GetSnapshot() != nil {
		value := SignedSnapshotFromProto(message.GetSnapshot())
		snapshot = &value
	}
	return snapshot, message.GetError()
}

// QuotaReport is the client-to-manager usage increment.
func QuotaReportToProto(report protocol.QuotaReport) *pb.QuotaReport {
	return &pb.QuotaReport{
		PeerId:          report.PeerID,
		Increments:      mapSlice(report.Increments, BudgetIncrementToProto),
		ReportedAt:      formatTime(report.ReportedAt),
		ProtocolVersion: report.ProtocolVersion,
	}
}

func QuotaReportFromProto(message *pb.QuotaReport) protocol.QuotaReport {
	if message == nil {
		return protocol.QuotaReport{}
	}
	return protocol.QuotaReport{
		PeerID:          message.GetPeerId(),
		Increments:      mapSlice(message.GetIncrements(), BudgetIncrementFromProto),
		ReportedAt:      parseTime(message.GetReportedAt()),
		ProtocolVersion: message.GetProtocolVersion(),
	}
}

func BudgetIncrementToProto(increment protocol.BudgetIncrement) *pb.BudgetIncrement {
	return &pb.BudgetIncrement{BudgetId: increment.BudgetID, Bytes: increment.Bytes}
}

func BudgetIncrementFromProto(message *pb.BudgetIncrement) protocol.BudgetIncrement {
	if message == nil {
		return protocol.BudgetIncrement{}
	}
	return protocol.BudgetIncrement{BudgetID: message.GetBudgetId(), Bytes: message.GetBytes()}
}
