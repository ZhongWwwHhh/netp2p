import type { Snapshot } from './types';
import { QuorumSize, signerCount } from './quorum';

// Default production committee: n=3, f=0, quorum=3. A snapshot's certified
// committeeConfig.threshold still takes precedence over this fallback.
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
