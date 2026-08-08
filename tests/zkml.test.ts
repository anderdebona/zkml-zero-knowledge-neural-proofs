import { describe, it, expect } from 'vitest';
import { ArithmeticNeuralCircuit } from '../src/zkp/circuit.js';
import { ZKMLProverEngine } from '../src/zkp/snark-prover.js';

describe('Zero-Knowledge Machine Learning (zkML) Tests', () => {
  it('should evaluate linear neural circuit W * x + b accurately', () => {
    const weights = [2, 3];
    const input = [4, 5];
    const bias = 1;

    const out = ArithmeticNeuralCircuit.evaluateCircuit(weights, input, bias);
    expect(out).toBe(24); // (2*4 + 3*5) + 1 = 8 + 15 + 1 = 24
  });

  it('should generate valid Zero-Knowledge proof and verify successfully', () => {
    const proof = ZKMLProverEngine.generateProof([10, 20], [1, 2], 5);
    expect(proof.publicOutput).toBe(55); // (10*1 + 20*2) + 5 = 55

    const isValid = ZKMLProverEngine.verifyProof(proof);
    expect(isValid).toBe(true);
  });
});
