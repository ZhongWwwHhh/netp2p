// Mirrors internal/bft: a fixed 4-member committee tolerates 1 fault, so a
// certificate needs 2f+1 = 3 signatures.
export const CommitteeSize = 4;
export const FaultLimit = 1;
export const QuorumSize = CommitteeSize - FaultLimit;
