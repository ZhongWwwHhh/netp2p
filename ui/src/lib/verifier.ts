import type { Snapshot } from './types';
import { QuorumSize, signerCount } from './quorum';

// Fixed 4-of-3 committee: n=4, f=1, quorum=2f+1.
export const QUORUM = QuorumSize;

/**
 * Structural sanity check only. Cryptographic verification (Ed25519
 * signatures over a canonical state hash) is intentionally NOT implemented
 * yet, so this must never be presented to the user as proof that a snapshot
 * is authentic.
 */
export function verifySnapshot(snapshot: Snapshot | null | undefined): boolean {
  if (!snapshot || !snapshot.qc || !snapshot.state) return false;
  const contributions = signerCount(snapshot.qc.signerBitmap);
  const threshold = snapshot.committeeConfig?.threshold ?? QUORUM;
  return snapshot.qc.height === snapshot.height
    && Boolean(snapshot.qc.aggregateSignature)
    && contributions >= threshold;
}
