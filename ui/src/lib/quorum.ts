// Mirrors the production manifest: a 3-member committee with no fault budget,
// so every certificate needs all 3 signatures.
export const CommitteeSize = 3;
export const FaultLimit = 0;
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
