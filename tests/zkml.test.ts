import { describe, it, expect } from 'vitest';
import { ZKMLProverEngine } from '../src/zkp/snark-prover.js';
import { ArithmeticNeuralCircuit } from '../src/zkp/circuit.js';
import { MerkleCommitmentScheme } from '../src/zkp/merkle-commitment.js';
import { BatchVerifier } from '../src/zkp/batch-verifier.js';

describe('Arithmetic Neural Circuit', () => {
  it('should compute W·x + b correctly', () => {
    const result = ArithmeticNeuralCircuit.evaluateCircuit([2, 3], [4, 5], 1);
    expect(result).toBe(2 * 4 + 3 * 5 + 1); // 24
  });

  it('should throw on dimension mismatch', () => {
    expect(() => ArithmeticNeuralCircuit.evaluateCircuit([1, 2], [1], 0)).toThrow();
  });
});

describe('zkML Prover Engine', () => {
  it('should generate and verify a valid proof', () => {
    const proof = ZKMLProverEngine.generateProof([42, 108], [1, 2], 7);
    expect(proof.proofHash).toMatch(/^0xpi_/);
    expect(proof.publicOutput).toBe(42 * 1 + 108 * 2 + 7);
    expect(ZKMLProverEngine.verifyProof(proof)).toBe(true);
  });

  it('should reject tampered proofs', () => {
    const proof = ZKMLProverEngine.generateProof([10, 20], [1, 1], 0);
    proof.proofHash = '0xINVALID';
    expect(ZKMLProverEngine.verifyProof(proof)).toBe(false);
  });
});

describe('Merkle Commitment Scheme', () => {
  it('should commit to model weights and return a root hash', () => {
    const scheme = new MerkleCommitmentScheme();
    const root = scheme.commit([42, 108, 256, 512]);
    expect(root).toBeTruthy();
    expect(root.length).toBe(64); // SHA-256 hex
  });

  it('should generate valid inclusion proofs', () => {
    const scheme = new MerkleCommitmentScheme();
    scheme.commit([10, 20, 30, 40]);
    const proof = scheme.generateProof(0);
    expect(proof.isValid).toBe(true);
    expect(proof.root).toBe(scheme.getRoot());
  });

  it('should verify correct Merkle proofs', () => {
    const scheme = new MerkleCommitmentScheme();
    scheme.commit([100, 200, 300, 400]);
    const proof = scheme.generateProof(2);
    const verified = MerkleCommitmentScheme.verifyProof(proof);
    expect(verified).toBe(true);
  });

  it('should reject proofs with tampered root', () => {
    const scheme = new MerkleCommitmentScheme();
    scheme.commit([5, 10, 15, 20]);
    const proof = scheme.generateProof(1);
    proof.root = 'tampered_root_hash';
    const verified = MerkleCommitmentScheme.verifyProof(proof);
    expect(verified).toBe(false);
  });
});

describe('Batch Verifier', () => {
  it('should verify a batch of valid proofs', () => {
    const proofs = BatchVerifier.generateBenchmarkBatch(10);
    const result = BatchVerifier.verifyBatch(proofs);
    expect(result.totalProofs).toBe(10);
    expect(result.allValid).toBe(true);
    expect(result.validProofs).toBe(10);
  });

  it('should detect invalid proofs in a batch', () => {
    const proofs = BatchVerifier.generateBenchmarkBatch(5);
    proofs[2].proofHash = '0xINVALID';
    const result = BatchVerifier.verifyBatch(proofs);
    expect(result.allValid).toBe(false);
    expect(result.invalidProofs).toBe(1);
  });

  it('should run benchmark across multiple batch sizes', () => {
    const benchmarks = BatchVerifier.benchmark([10, 50, 100]);
    expect(benchmarks.length).toBe(3);
    expect(benchmarks[0].batchSize).toBe(10);
    expect(benchmarks[2].batchSize).toBe(100);
    benchmarks.forEach((b) => expect(b.throughputProofsPerSec).toBeGreaterThan(0));
  });
});
