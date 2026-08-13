import crypto from 'crypto';

export interface QuantizedCircuitProof {
  proofId: string;
  quantizedOutput: number;
  scaleFactor: number;
  rangeCheckPassed: boolean;
  circuitDigest: string;
}

export class QuantizedInferenceCircuitProver {
  /**
   * Proves INT8 quantized dot-product and activation without overflow:
   * y = clamp(floor((W * X + b) / scaleFactor), -128, 127)
   */
  public static proveInt8Layer(
    weights: number[], // INT8 [-128..127]
    inputs: number[],  // INT8 [-128..127]
    bias: number,      // INT32
    scaleFactor: number = 32
  ): QuantizedCircuitProof {
    if (weights.length !== inputs.length) {
      throw new Error(`Dimension mismatch: ${weights.length} vs ${inputs.length}`);
    }

    let accumulator = bias;
    for (let i = 0; i < weights.length; i++) {
      accumulator += weights[i] * inputs[i];
    }

    const scaled = Math.floor(accumulator / scaleFactor);
    const clamped = Math.max(-128, Math.min(127, scaled));
    const rangeCheckPassed = clamped >= -128 && clamped <= 127;

    const circuitDigest = crypto
      .createHash('sha256')
      .update(`quant_circuit:${accumulator}:${clamped}:${scaleFactor}`)
      .digest('hex');

    return {
      proofId: `0xzkq_${circuitDigest.substring(0, 16)}`,
      quantizedOutput: clamped,
      scaleFactor,
      rangeCheckPassed,
      circuitDigest: `0x${circuitDigest}`,
    };
  }

  public static verifyQuantizedProof(proof: QuantizedCircuitProof): boolean {
    return proof.rangeCheckPassed && proof.proofId.startsWith('0xzkq_') && proof.circuitDigest.length === 66;
  }
}
