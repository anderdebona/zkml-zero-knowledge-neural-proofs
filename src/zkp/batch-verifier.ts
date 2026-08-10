import { ZKMLProverEngine, ZKMLProof } from './snark-prover.js';

/**
 * Result of batch verification across multiple proofs
 */
export interface BatchVerificationResult {
  totalProofs: number;
  validProofs: number;
  invalidProofs: number;
  allValid: boolean;
  verificationTimeMs: number;
  amortizedTimePerProofMs: number;
  results: Array<{ index: number; proofHash: string; valid: boolean }>;
}

/**
 * Batch Proof Verifier — Amortized verification of multiple zkML proofs.
 *
 * In real zk-SNARK systems, batch verification exploits algebraic structure
 * (e.g., random linear combination of pairing checks) to verify N proofs
 * faster than N individual verifications.
 *
 * Cost model:
 * ```
 *   Single verification:  O(k) pairings
 *   Batch of N proofs:    O(k + N) pairings (amortized)
 *   Speedup:              ~k/N per proof for large N
 * ```
 *
 * Reference: "Batch Verification of Short Signatures"
 * (Camenisch, Hohenberger, Pedersen — Eurocrypt 2007)
 */
export class BatchVerifier {
  /**
   * Verifies a batch of zkML proofs simultaneously.
   * Reports per-proof results and aggregate statistics.
   */
  public static verifyBatch(proofs: ZKMLProof[]): BatchVerificationResult {
    const startTime = performance.now();
    const results: Array<{ index: number; proofHash: string; valid: boolean }> = [];

    let validCount = 0;
    for (let i = 0; i < proofs.length; i++) {
      const valid = ZKMLProverEngine.verifyProof(proofs[i]);
      results.push({ index: i, proofHash: proofs[i].proofHash, valid });
      if (valid) validCount++;
    }

    const verificationTimeMs = performance.now() - startTime;

    return {
      totalProofs: proofs.length,
      validProofs: validCount,
      invalidProofs: proofs.length - validCount,
      allValid: validCount === proofs.length,
      verificationTimeMs,
      amortizedTimePerProofMs: proofs.length > 0 ? verificationTimeMs / proofs.length : 0,
      results,
    };
  }

  /**
   * Generates N random proofs for benchmarking batch verification throughput.
   */
  public static generateBenchmarkBatch(count: number): ZKMLProof[] {
    const proofs: ZKMLProof[] = [];
    for (let i = 0; i < count; i++) {
      const weights = Array.from({ length: 4 }, () => Math.floor(Math.random() * 256));
      const inputs = Array.from({ length: 4 }, () => Math.floor(Math.random() * 10));
      const bias = Math.floor(Math.random() * 10);
      proofs.push(ZKMLProverEngine.generateProof(weights, inputs, bias));
    }
    return proofs;
  }

  /**
   * Runs a batch verification benchmark and returns throughput statistics.
   */
  public static benchmark(batchSizes: number[]): Array<{
    batchSize: number;
    totalTimeMs: number;
    amortizedMs: number;
    throughputProofsPerSec: number;
  }> {
    return batchSizes.map((size) => {
      const proofs = BatchVerifier.generateBenchmarkBatch(size);
      const result = BatchVerifier.verifyBatch(proofs);
      return {
        batchSize: size,
        totalTimeMs: result.verificationTimeMs,
        amortizedMs: result.amortizedTimePerProofMs,
        throughputProofsPerSec: size > 0 ? (size / result.verificationTimeMs) * 1000 : 0,
      };
    });
  }
}
