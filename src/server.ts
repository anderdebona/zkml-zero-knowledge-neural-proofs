import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { ZKMLProverEngine } from './zkp/snark-prover.js';
import { Halo2PolynomialCommitment } from './zkp/polynomial-commitment.js';
import { QuantizedInferenceCircuitProver } from './zkp/quantized-prover.js';
import { PlookupArgumentTable } from './zkp/plookup-argument-table.js';
import { ZKTransformerLayerProver } from './zkp/zk-transformer-layer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3011;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const secretWeights = [42, 108, 256];
const bias = 7;
const plookup = new PlookupArgumentTable();

app.post('/api/zkml/prove', (req, res) => {
  const { inputVector = [1, 2, 3] } = req.body;
  const proof = ZKMLProverEngine.generateProof(secretWeights, inputVector, bias);
  const isValid = ZKMLProverEngine.verifyProof(proof);

  res.json({
    proof,
    isValid,
  });
});

app.post('/api/zkml/polynomial-proof', (req, res) => {
  const { coefficients = [5, -3, 2, 1], evalPoint = 3 } = req.body;
  const commitment = Halo2PolynomialCommitment.commit(coefficients);
  const opening = Halo2PolynomialCommitment.open(coefficients, evalPoint);
  const isValid = Halo2PolynomialCommitment.verify(commitment, evalPoint, opening.evaluatedValue, opening, coefficients);

  res.json({
    commitment,
    opening,
    isValid,
  });
});

app.post('/api/zkml/quantized-proof', (req, res) => {
  const { inputs = [10, 20, 30], weights = [3, 2, 1], biasVal = 5 } = req.body;
  const proof = QuantizedInferenceCircuitProver.proveInt8Layer(weights, inputs, biasVal, 32);
  const isValid = QuantizedInferenceCircuitProver.verifyQuantizedProof(proof);

  res.json({
    proof,
    isValid,
  });
});

app.post('/api/zkml/plookup', (req, res) => {
  const { inputs = [-12, -4, 0, 8, 16] } = req.body;
  const proof = plookup.generateLookupProof(inputs);
  res.json(proof);
});

app.post('/api/zkml/transformer-proof', (req, res) => {
  const qMatrix = [
    [1.0, 0.5, -0.2, 0.8],
    [0.2, 1.1, 0.4, -0.5],
    [0.8, -0.3, 0.9, 0.1]
  ];
  const kMatrix = [
    [0.9, 0.4, -0.1, 0.7],
    [0.1, 1.0, 0.3, -0.4],
    [0.7, -0.2, 0.8, 0.2]
  ];
  const vMatrix = [
    [0.5, 0.2, 0.8, 0.1],
    [0.4, 0.6, 0.3, 0.9],
    [0.9, 0.1, 0.5, 0.4]
  ];

  const proof = ZKTransformerLayerProver.generateAttentionProof({ qMatrix, kMatrix, vMatrix });
  res.json(proof);
});

app.listen(PORT, () => {
  console.log(`🚀 zkML Zero-Knowledge Prover v5.0.0 on http://localhost:${PORT}`);
});
