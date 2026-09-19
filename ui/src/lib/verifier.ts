import type { Snapshot } from './types';

// Fixed 4-of-3 committee: n=4, f=1, quorum=2f+1.
export const QUORUM = 3;

function asArray<T>(value: readonly T[] | null | undefined): T[] {
  return Array.isArray(value) ? [...value] : [];
}

/**
 * Structural sanity check only. Cryptographic verification (Ed25519
 * signatures over a canonical state hash) is intentionally NOT implemented
 * yet, so this must never be presented to the user as proof that a snapshot
 * is authentic.
 */
export function verifySnapshot(snapshot: Snapshot | null | undefined): boolean {
  if (!snapshot || !snapshot.qc || !snapshot.state) return false;
  const known = new Set(asArray(snapshot.committee).map((member) => member.id));
  const signers = asArray(snapshot.qc.signers);
  const signatures = asArray(snapshot.qc.signatures);
  const uniqueSigners = new Set(signers);
  return snapshot.qc.height === snapshot.height
    && signatures.length === signers.length
    && uniqueSigners.size === signers.length
    && signers.every((signer) => known.has(signer))
    && uniqueSigners.size >= QUORUM;
}
