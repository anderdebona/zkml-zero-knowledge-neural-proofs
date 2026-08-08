#!/usr/bin/env node
import { ZKMLProverEngine } from './zkp/snark-prover.js';

console.log(`
===========================================================
  🔐 ZERO-KNOWLEDGE ML (zkML) PROVER CLI [v1.0.0]
  Author: anderdebona
===========================================================
`);

const secretWeights = [42, 108, 256];
const inputVector = [1, 2, 3];
const bias = 7;

console.log('🔒 Secret Model Weights W: [PRIVATE]');
console.log('📥 Public Input Vector x:', inputVector);

const proof = ZKMLProverEngine.generateProof(secretWeights, inputVector, bias);
const isValid = ZKMLProverEngine.verifyProof(proof);

console.log('\n📜 Cryptographic Proof pi:');
console.log(JSON.stringify(proof, null, 2));

console.log(`\n🛡️ Verification Result: ${isValid ? '✅ VALID PROOF' : '❌ INVALID'}`);
