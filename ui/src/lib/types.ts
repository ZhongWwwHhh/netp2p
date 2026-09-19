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
  nextIpOffset: number;
}

export interface Snapshot {
  epoch: number;
  height: number;
  stateHash: string;
  state: State;
  committee: CommitteeMember[];
  qc: QC;
}

export type StateTransition =
  | { type: 'upsert_group'; group: Group }
  | { type: 'remove_group'; targetId: string }
  | { type: 'upsert_policy'; policy: Policy }
  | { type: 'remove_policy'; targetId: string }
  | { type: 'upsert_setup_key'; setupKeyRecord: SetupKey };

export interface Bootstrap {
  peerId: string;
  publicKey: string;
  webrtcAddresses: string[];
  apiProtocol: string;
  apiBase: string;
  networkId: string;
  committee: CommitteeMember[];
}
