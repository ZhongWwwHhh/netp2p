// Mirrors internal/bft: a fixed 4-member committee tolerates 1 fault, so a
// certificate needs 2f+1 = 3 signatures.
export const CommitteeSize = 4;
export const FaultLimit = 1;
export const QuorumSize = CommitteeSize - FaultLimit;

// The quorum certificate carries a threshold BLS signer bitmap rather than a
// list of per-member signatures, so the contributing share count is derived
// from the set bits.
export function signerCount(bitmap: number[] | string | undefined): number {
  if (!bitmap) return 0;
  const bytes = typeof bitmap === 'string'
    ? Array.from(atob(bitmap), (char) => char.charCodeAt(0))
    : bitmap;
  return bytes.reduce((total, byte) => {
    let count = 0;
    for (let bit = 0; bit < 8; bit += 1) if (byte & (1 << bit)) count += 1;
    return total + count;
  }, 0);
}
