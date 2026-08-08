import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { ZKMLProverEngine } from './zkp/snark-prover.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3011;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

const secretWeights = [42, 108, 256];
const bias = 7;

app.post('/api/zkml/prove', (req, res) => {
  const { inputVector = [1, 2, 3] } = req.body;
  const proof = ZKMLProverEngine.generateProof(secretWeights, inputVector, bias);
  const isValid = ZKMLProverEngine.verifyProof(proof);

  res.json({
    proof,
    isValid,
  });
});

app.listen(PORT, () => {
  console.log(`🚀 zkML Zero-Knowledge Prover running on http://localhost:${PORT}`);
});
