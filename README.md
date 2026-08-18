# zkML Zero-Knowledge Neural Proofs Engine 🔐 🧠

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Version](https://img.shields.io/badge/Version-v5.0.0%20Ultra-00d2ff?style=for-the-badge)](https://github.com/anderdebona/zkml-zero-knowledge-neural-proofs)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-Passing%20100%25-success?style=for-the-badge&logo=githubactions)](https://github.com/anderdebona/zkml-zero-knowledge-neural-proofs/actions)

<br />

**PhD-Grade Zero-Knowledge Machine Learning (zkML): Plookup Activation Lookup Tables, ZK Transformer Attention Provers, Halo2 Polynomial Commitments & INT8 Quantized Neural Circuits**

*Engineered with precision by **[anderdebona](https://github.com/anderdebona)***

</div>

---

## 📌 Technical Summary & Mathematical Foundations

This repository implements a **Zero-Knowledge Machine Learning (zkML)** proving engine. It allows cryptographic verification of private neural network inference without revealing model parameters or private inputs. It features Plookup multiset lookup tables for non-linear activations (GELU, SiLU), arithmetic circuit proofs for Transformer Self-Attention layers, and Halo2-style polynomial commitments.

---

## 🔬 Mathematical Formulations

### 1. Plookup Multiset Equality Grand Product
$$\prod_{i=1}^n (1 + \beta)(f_i + \gamma) \cdot \prod_{j=1}^d (1 + \beta)(t_j + \gamma) = \prod_{k=1}^{n+d} (s_k + \gamma)(1 + \beta)$$

### 2. Zero-Knowledge Multi-Head Attention Verification
$$\text{Attention}(Q, K, V) = \text{Softmax}\left( \frac{Q K^T}{\sqrt{d_k}} \right) V$$

---

## ⚡ What's New in v5.0.0

- 📑 **`PlookupArgumentTable`**: Exact lookup table verification for non-linear activations avoiding polynomial degree explosion.
- 🤖 **`ZKTransformerLayerProver`**: Succinct R1CS constraint generation for Scaled Dot-Product Attention and LayerNorm.
- 🎛️ **Studio v5.0.0**: Interactive Plookup table explorer and ZK Transformer layer proof inspector.
- 🧪 **20/20 Tests Passing**: 100% Vitest coverage across R1CS circuits, Merkle trees, Halo2 KZG, and SNARKs.

---

## 🚀 Quickstart & Interactive Studio

```bash
git clone https://github.com/anderdebona/zkml-zero-knowledge-neural-proofs.git
cd zkml-zero-knowledge-neural-proofs
npm install
npm test
npm run build
npm start
# Open http://localhost:3011
```

---

## 📄 License & Citation
MIT License © 2026 anderdebona. See [CITATION.cff](CITATION.cff) for academic attribution.
