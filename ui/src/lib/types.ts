export type Effect = 'allow' | 'deny';
export type Direction = 'unidirectional' | 'bidirectional';

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
}

export interface Group {
  id: string;
  userIds?: string[];
  peerIds?: string[];
  managed?: boolean;
  ssoClaim?: string;
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
}

export interface SetupKey {
  key: string;
  groups: string[];
}

export interface Budget {
  id: string;
  subjectType: string;
  subjectId: string;
  dailyBytes: number;
  monthlyBytes: number;
  peakBps: number;
  relayCostLimit: number;
  onExhausted: string;
  usedDailyBytes: number;
  usedMonthlyBytes: number;
}

export interface Peer {
  peerId: string;
  overlayIp: string;
  addresses?: string[];
  groups?: string[];
  hostname?: string;
  os?: string;
  clientVersion?: string;
}

export interface CommitteeMember {
  id: string;
  peerId: string;
  address: string;
  publicKey?: string;
  listenAddr?: string;
}

export interface QC {
  height: number;
  round: number;
  stateHash: string;
  transitionHash: string;
  signers: string[];
  signatures: string[];
}

export interface State {
  networkId: string;
  overlayCidr: string;
  peers: Peer[];
  groups: Group[];
  policies: Policy[];
  routes: Route[];
  budgets: Budget[];
  setupKeys: SetupKey[];
  nameservers: Nameserver[];
  zones: DNSZone[];
  dnsSettings: DNSSettings;
  nextIpOffset: number;
}

export interface Snapshot {
  epoch: number;
  height: number;
  stateHash: string;
  state: State;
  committee: CommitteeMember[];
  qc: QC;
  transition: StateTransition;
  leaderId: string;
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

export type StateTransition =
  | { type: 'upsert_group'; group: Group }
  | { type: 'remove_group'; targetId: string }
  | { type: 'upsert_policy'; policy: Policy }
  | { type: 'remove_policy'; targetId: string }
  | { type: 'upsert_route'; route: Route }
  | { type: 'remove_route'; targetId: string }
  | { type: 'upsert_budget'; budget: Budget }
  | { type: 'remove_budget'; targetId: string }
  | { type: 'upsert_setup_key'; setupKeyRecord: SetupKey }
  | { type: 'remove_setup_key'; targetId: string }
  | { type: 'upsert_nameserver'; nameserver: Nameserver }
  | { type: 'remove_nameserver'; targetId: string }
  | { type: 'upsert_zone'; zone: DNSZone }
  | { type: 'remove_zone'; targetId: string }
  | { type: 'update_dns_settings'; dnsSettings: DNSSettings };

export interface Bootstrap {
  peerId: string;
  publicKey: string;
  webrtcAddresses: string[];
  apiProtocol: string;
  apiBase: string;
  networkId: string;
  version: string;
  committee: CommitteeMember[];
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
