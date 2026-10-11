export type Effect = 'allow' | 'deny';
export type Direction = 'unidirectional' | 'bidirectional';
export type FlowClass = 'latency' | 'throughput' | 'cost' | 'reliability' | 'realtime';

export interface Service {
  protocol: string;
  startPort: number;
  endPort: number;
}

export interface Policy {
  id: string;
  sourceGroups: string[];
  destinationGroups: string[];
  services: Service[];
  effect: Effect;
  direction: Direction;
  priority: number;
  postureRequirements?: string[];
  linkConstraints?: string[];
  flowClass?: FlowClass | '';
}

export interface Group {
  id: string;
  name?: string;
  userIds?: string[];
  peerIds?: string[];
  managed?: boolean;
  ssoClaim?: string;
  issued?: string;
}

export interface User {
  id: string;
  email?: string;
  name?: string;
  role: string;
  autoGroups?: string[];
  blocked?: boolean;
  issued?: string;
  lastLogin?: string;
}

export interface NetworkSettings {
  dnsDomain?: string;
  loginExpirationDays?: number;
  jwtGroupsEnabled?: boolean;
  jwtGroupsClaimName?: string;
  jwtAllowGroups?: string[];
  linkMinBandwidthMbps?: number;
  viaManagerLatencyAdvantageMs?: number;
  viaManagerLossAdvantagePct?: number;
  linkProbeIntervalSeconds?: number;
  linkProbeTimeoutMs?: number;
  viaManagerEnabled?: boolean;
  directPathEnabled?: boolean;
  maxManagerHops?: number;
  probeBandwidthBudgetKb?: number;
  quotaEnforcementEnabled?: boolean;
  quotaReportIntervalSeconds?: number;
  defaultFlowClass?: FlowClass | '';
  exitNodeEnabled?: boolean;
}

export type PathKind = 'direct' | 'via_manager' | 'multi_hop';

export interface RoutingDomainKey {
  sourceManagerId: string;
  sourceGroupId: string;
  destinationScope: string;
  flowClass: FlowClass;
}

export interface RoutingDomain {
  id: string;
  key: RoutingDomainKey;
  pathFamilyIds: string[];
  policyIds: string[];
  services?: Service[];
  maxHops?: number;
  requiresAdmission: boolean;
}

export interface PathFamily {
  id: string;
  kind: PathKind;
  managerHops?: string[];
  sourceGroups: string[];
  destinationScopes: string[];
  flowClasses: FlowClass[];
  maxRttMilliseconds: number;
  maxJitterMilliseconds: number;
  maxLossPercent: number;
  minBandwidthMbps: number;
}

export interface PathSpec {
  id: string;
  kind: PathKind;
  managerHops?: string[];
  rttMilliseconds: number;
  lossPercent: number;
  bandwidthMbps: number;
  confidence: number;
  cost?: number;
}

export interface RouteAssignment {
  id: string;
  networkId: string;
  sourcePeerId: string;
  destinationPeerId: string;
  epoch: number;
  primary: PathSpec;
  fallbacks: PathSpec[];
  maxHops?: number;
  updatedAt: string;
  requiresAdmission: boolean;
}

export interface Route {
  id: string;
  destination: string;
  routingGroup: string;
  distributionGroups: string[];
  metric: number;
  allowedPathTypes?: string[];
  maxHops?: number;
  budgetIds?: string[];
  masquerade?: boolean;
  flowClass?: FlowClass | '';
}

export interface SetupKey {
  id: string;
  name?: string;
  token?: string;
  tokenPrefix?: string;
  type?: string;
  groups: string[];
  expiresAt?: string;
  usageLimit?: number;
  usedCount?: number;
  revoked?: boolean;
  createdAt?: string;
  lastUsedAt?: string;
}

export type SetupKeyCreateInput = Pick<SetupKey, 'name' | 'type' | 'groups' | 'expiresAt' | 'usageLimit'>;

export interface SetupKeyCreation {
  token: string;
  snapshot: Snapshot;
}

export interface Budget {
  id: string;
  subjectType: string;
  subjectId: string;
  dailyBytes: number;
  monthlyBytes: number;
  peakBps: number;
  forwardingCostLimit: number;
  onExhausted: string;
  usedDailyBytes: number;
  usedMonthlyBytes: number;
  peakBurstBytes?: number;
}

export interface RoutingEpoch {
  networkId: string;
  snapshotHeight: number;
  version: number;
  generatedAt: string;
  expiresAt: string;
  candidateSetDigest: string;
  plannerDigest: string;
  managerId: string;
  signatureVerified: boolean;
  thresholdSigned: boolean;
  allocations: PathAllocation[];
}

export interface PathAllocation {
  key: RoutingDomainKey;
  paths: PathWeight[];
}

export interface PathWeight {
  pathId: string;
  weight: number;
  reason?: string;
}

export interface ManagerCapacityStatus {
  managerId: string;
  configured: boolean;
  monthlyBytes: number;
  usedBytes: number;
  remainingBytes: number;
  reserveBytes: number;
  countMode: string;
  resetDayUtc: number;
  softThresholdPercent: number;
  pressure: number;
  burnRateBytesPerSecond: number;
  projectedExhaustionSeconds: number;
  state: string;
  updatedAt: string;
}

export interface EdgeTelemetry {
  edgeId: string;
  managerId: string;
  queueDepth: number;
  queueDepthEwma: number;
  sendBytesPerSecond: number;
  dropRate: number;
  activeFlows: number;
  rttMilliseconds: number;
  jitterMilliseconds: number;
  lossPercent: number;
  measuredBandwidthMbps: number;
  monthlyUsedBytes: number;
  monthlyLimitBytes: number;
  updatedAt: string;
  source: string;
}

export interface DemandSample {
  peerId: string;
  sourceGroupId: string;
  destinationScope: string;
  flowClass: FlowClass;
  pathId: string;
  bytes: number;
  durationMs: number;
  observedAt: string;
}

export interface FECDiagnostics {
  enabled: boolean;
  defaultCodec: string;
  maxRedundancyPercent: number;
  classes: FECClassDiagnostics[];
}

export interface FECClassDiagnostics {
  flowClass: FlowClass;
  enabled: boolean;
  packets: number;
  recoveredPackets: number;
  generatedRedundancyPackets: number;
  overheadRatio: number;
  recoveredRatio: number;
  lastError?: string;
}

export interface RoutingStatus {
  networkId: string;
  snapshotHeight: number;
  generatedAt: string;
  mode: string;
  supportedFlowClasses: FlowClass[];
  domains: RoutingDomain[];
  pathFamilies: PathFamily[];
  epoch?: RoutingEpoch | null;
  managerCapacity: ManagerCapacityStatus[];
  telemetry: EdgeTelemetry[];
  demand: DemandSample[];
  fec: FECDiagnostics;
  problems: string[];
}

export interface Peer {
  peerId: string;
  overlayIp: string;
  addresses?: string[];
  groups?: string[];
  hostname?: string;
  os?: string;
  clientVersion?: string;
  userId?: string;
  dnsLabel?: string;
  lastLogin?: string;
  isExitNode?: boolean;
  posture?: string[];
}

export interface CommitteeMember {
  id: string;
  peerId: string;
  address: string;
  publicKey?: string;
  blsPublicKey?: string;
  listenAddr?: string;
  forwardingEnabled?: boolean;
}

export type ManagerJoinStatus = 'pending' | 'approved' | 'rejected' | 'activated';

export interface ManagerJoinRequest {
  id: string;
  managerId: string;
  peerId: string;
  address: string;
  listenAddr?: string;
  publicKey?: string;
  requestedAt: string;
  status: ManagerJoinStatus;
  reviewedBy?: string;
  reviewedAt?: string;
  reason?: string;
}

export interface QC {
  height: number;
  round: number;
  stateHash: string;
  transitionHash: string;
  // Threshold BLS: a single aggregated group signature plus a bitmap of the
  // committee shares that contributed.
  aggregateSignature?: string;
  signerBitmap?: number[] | string;
  committeeEpoch: number;
}

export interface AuditEvent {
  height: number;
  type: string;
  leaderId: string;
  actor?: Actor;
  signerBitmap?: number[] | string;
  stateHash: string;
  transitionHash: string;
  committeeEpoch: number;
}

export interface Diagnostics {
  protocolVersion: string;
  manager: string;
  networkId: string;
  height: number;
  quorumSize: number;
  committeeSize: number;
  peers: number;
  groups: number;
  policies: number;
  budgets: number;
  assignments: number;
  linkSegments: number;
  presence: Presence[];
  forwarding: { forwarded: number; dropped: number };
  quotaUsage: Budget[];
  alerts: Alert[];
  problems: string[];
}

// Alert is a manager-local operational condition. Alerts are not certified:
// two managers may see different transient state, so the console labels them
// as observations.
export interface Alert {
  id: string;
  rule: string;
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  firedAt: string;
}

export interface State {
  networkId: string;
  overlayCidr: string;
  peers: Peer[];
  users: User[];
  groups: Group[];
  policies: Policy[];
  routes: Route[];
  budgets: Budget[];
  setupKeys: SetupKey[];
  nameservers: Nameserver[];
  zones: DNSZone[];
  dnsSettings: DNSSettings;
  settings: NetworkSettings;
  assignments: RouteAssignment[];
  pathFamilies: PathFamily[];
  routingDomains: RoutingDomain[];
  managerJoins: ManagerJoinRequest[];
  nextIpOffset: number;
}

export interface Snapshot {
  epoch: number;
  height: number;
  stateHash: string;
  state: State;
  committee: CommitteeMember[];
  qc: QC;
  committeeConfig?: CommitteeConfig;
  transition: StateTransition;
  leaderId: string;
}

export interface CommitteeConfig {
  threshold: number;
  size: number;
  groupPublicKey?: string;
  committeeEpoch: number;
}

export interface Nameserver {
  id: string;
  name: string;
  groups: string[];
  matchDomains?: string[];
  servers: string[];
  primary?: boolean;
  enabled: boolean;
}

export interface DNSRecord {
  name: string;
  type: string;
  value: string;
  ttl?: number;
}

export interface DNSZone {
  id: string;
  domain: string;
  records: DNSRecord[];
  groups?: string[];
  enabled: boolean;
}

export interface DNSSettings {
  disabled: boolean;
  groups?: string[];
}

// Actor is the audit identity the manager attaches to a certified transition.
// The console only displays it; the server always overwrites whatever a caller
// sends, so it is evidence rather than a credential.
export interface Actor {
  id: string;
  name?: string;
  role?: string;
  static?: boolean;
}

export type StateTransition = (
  | { type: 'upsert_group'; group: Group }
  | { type: 'remove_group'; targetId: string }
  | { type: 'upsert_policy'; policy: Policy }
  | { type: 'remove_policy'; targetId: string }
  | { type: 'upsert_route'; route: Route }
  | { type: 'remove_route'; targetId: string }
  | { type: 'upsert_budget'; budget: Budget }
  | { type: 'remove_budget'; targetId: string }
  | { type: 'upsert_setup_key'; setupKeyRecord: SetupKey }
  | { type: 'revoke_setup_key'; targetId: string }
  | { type: 'remove_setup_key'; targetId: string }
  | { type: 'upsert_nameserver'; nameserver: Nameserver }
  | { type: 'remove_nameserver'; targetId: string }
  | { type: 'upsert_zone'; zone: DNSZone }
  | { type: 'remove_zone'; targetId: string }
  | { type: 'update_dns_settings'; dnsSettings: DNSSettings }
  | { type: 'update_user_role'; user: User }
  | { type: 'update_user_credentials'; targetId: string; user: Partial<User> }
  | { type: 'set_user_blocked'; user: User }
  | { type: 'remove_user'; targetId: string }
  | { type: 'update_network_settings'; settings: NetworkSettings }
  | { type: 'update_peer'; peer: Peer }
  | { type: 'update_route_assignment'; assignment: RouteAssignment }
  | { type: 'remove_route_assignment'; targetId: string }
  | { type: 'upsert_path_family'; pathFamily: PathFamily }
  | { type: 'remove_path_family'; targetId: string }
  | { type: 'upsert_routing_domain'; routingDomain: RoutingDomain }
  | { type: 'remove_routing_domain'; targetId: string }
  | { type: 'update_committee'; committee: CommitteeMember[]; committeeConfig?: CommitteeConfig }
  | { type: 'rotate_committee_keys'; committeeConfig?: CommitteeConfig }
  | { type: 'submit_manager_join'; managerJoin: ManagerJoinRequest }
  | { type: 'review_manager_join'; managerJoin: ManagerJoinRequest }
  | { type: 'activate_committee'; committee: CommitteeMember[]; committeeConfig?: CommitteeConfig }
) & { actor?: Actor };

// AdmissionReport is a client-observed, non-certified end-to-end probe result.
export interface AdmissionReport {
  assignmentId: string;
  pathId: string;
  ok: boolean;
  rttMs: number;
  lossPct: number;
  observedAt: string;
}

export type Operation = 'create' | 'read' | 'update' | 'delete';

export interface Identity {
  subject?: string;
  userId?: string;
  email?: string;
  name?: string;
  role: string;
  static?: boolean;
}

export interface SessionInfo {
  identity: Identity;
  permissions: Record<string, Operation[]>;
}

export interface AuthStatus {
  needsOwner: boolean;
  localLogin: boolean;
}

export interface LoginResponse {
  identity: Identity;
  permissions: Record<string, Operation[]>;
  sessionToken: string;
  expiresAt?: string;
}

export interface BootstrapOIDC {
  issuer: string;
  clientId: string;
  scopes: string[];
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  redirectUri?: string;
}

export interface Bootstrap {
  peerId: string;
  publicKey: string;
  webrtcAddresses: string[];
  apiProtocol: string;
  apiBase: string;
  networkId: string;
  version: string;
  committee: CommitteeMember[];
  oidc?: BootstrapOIDC;
}

export interface Presence {
  peerId: string;
  online: boolean;
  lastSeen: string;
  remoteAddr?: string;
  observer: string;
  updatedAt: string;
}

export interface ActivityEntry extends Snapshot {}
