import { describe, it, expect } from 'vitest';
import { ZKMLProverEngine } from '../src/zkp/snark-prover.js';
import { ArithmeticNeuralCircuit } from '../src/zkp/circuit.js';
import { MerkleCommitmentScheme } from '../src/zkp/merkle-commitment.js';
import { BatchVerifier } from '../src/zkp/batch-verifier.js';
import { RecursiveSNARKComposer } from '../src/zkp/recursive-snark.js';
import { WitnessGenerator } from '../src/zkp/witness-generator.js';

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

describe('Recursive SNARK Composer', () => {
  it('should create base proofs', () => {
    const proof = RecursiveSNARKComposer.createBaseProof(42);
    expect(proof.length).toBe(64);
  });

  it('should compose proofs recursively', () => {
    const base = RecursiveSNARKComposer.createBaseProof(1);
    const composed = RecursiveSNARKComposer.compose(base, 'step-2');
    expect(composed.isValid).toBe(true);
    expect(composed.composedHash.length).toBe(64);
  });

  it('should build IVC chain', () => {
    const chain = RecursiveSNARKComposer.buildIVCChain([1, 2, 3, 4, 5]);
    expect(chain.chainLength).toBe(5);
    expect(chain.allValid).toBe(true);
    expect(chain.finalProof.length).toBe(64);
  });
});

describe('Witness Generator', () => {
  it('should generate valid witness for linear computation', () => {
    const witness = WitnessGenerator.generateLinearWitness([2, 3], [4, 5], 1);
    expect(witness.isSatisfied).toBe(true);
    expect(witness.numPublic).toBeGreaterThan(0);
    expect(witness.numPrivate).toBeGreaterThan(0);
  });

  it('should separate public and private assignments', () => {
    const witness = WitnessGenerator.generateLinearWitness([1, 2], [3, 4], 0);
    const publicVars = witness.assignments.filter(a => a.isPublic);
    const privateVars = witness.assignments.filter(a => !a.isPublic);
    expect(publicVars.length).toBe(witness.numPublic);
    expect(privateVars.length).toBe(witness.numPrivate);
  });
});

describe('Halo2PolynomialCommitment (v4.0.0)', () => {
  it('should commit to polynomial and verify opening proof at evaluation point', async () => {
    const { Halo2PolynomialCommitment } = await import('../src/zkp/polynomial-commitment.js');
    const coeffs = [3, 2, 1]; // p(x) = 3 + 2x + x^2
    const commit = Halo2PolynomialCommitment.commit(coeffs);
    expect(commit.commitmentHash.startsWith('0xpoly_')).toBe(true);

    const pointZ = 2; // p(2) = 3 + 4 + 4 = 11
    const opening = Halo2PolynomialCommitment.open(coeffs, pointZ);
    expect(opening.evaluatedValue).toBe(11);

    const isValid = Halo2PolynomialCommitment.verify(commit, pointZ, 11, opening, coeffs);
    expect(isValid).toBe(true);
  });
});

describe('QuantizedInferenceCircuitProver (v4.0.0)', () => {
  it('should generate valid INT8 quantized proof within bounded range', async () => {
    const { QuantizedInferenceCircuitProver } = await import('../src/zkp/quantized-prover.js');
    const weights = [10, -5, 20];
    const inputs = [4, 8, 2];
    const bias = 16;
    // 10*4 + (-5)*8 + 20*2 + 16 = 40 - 40 + 40 + 16 = 56
    // scaled = floor(56 / 8) = 7

    const proof = QuantizedInferenceCircuitProver.proveInt8Layer(weights, inputs, bias, 8);
    expect(proof.quantizedOutput).toBe(7);
    expect(proof.rangeCheckPassed).toBe(true);
    expect(QuantizedInferenceCircuitProver.verifyQuantizedProof(proof)).toBe(true);
  });
});

describe('PlookupArgumentTable (v5.0.0)', () => {
  it('should verify non-linear GELU activation lookups and generate grand product proof', async () => {
    const { PlookupArgumentTable } = await import('../src/zkp/plookup-argument-table.js');
    const plookup = new PlookupArgumentTable();

    const inputs = [-10, 0, 5, 20];
    const proof = plookup.generateLookupProof(inputs);

    expect(proof.isValid).toBe(true);
    expect(proof.tableSize).toBeGreaterThan(200);
    expect(proof.grandProductCommitment.length).toBe(64);
  });
});

describe('ZKTransformerLayerProver (v5.0.0)', () => {
  it('should generate Zero-Knowledge attention matrix and LayerNorm constraints proof', async () => {
    const { ZKTransformerLayerProver } = await import('../src/zkp/zk-transformer-layer.js');
    const qMatrix = [
      [1.0, 0.5, -0.2, 0.8],
      [0.2, 1.1, 0.4, -0.5]
    ];
    const kMatrix = [
      [0.9, 0.4, -0.1, 0.7],
      [0.1, 1.0, 0.3, -0.4]
    ];
    const vMatrix = [
      [0.5, 0.2, 0.8, 0.1],
      [0.4, 0.6, 0.3, 0.9]
    ];

    const proof = ZKTransformerLayerProver.generateAttentionProof({ qMatrix, kMatrix, vMatrix });
    expect(proof.isProofValid).toBe(true);
    expect(proof.seqLength).toBe(2);
    expect(proof.headDim).toBe(4);
    expect(proof.snarkConstraintCount).toBeGreaterThan(0);
    expect(proof.proofSignature.length).toBe(64);
  });
});


