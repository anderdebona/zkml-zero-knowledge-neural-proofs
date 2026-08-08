export interface NeuralLayerCircuit {
  weights: number[];
  bias: number;
  inputVector: number[];
  publicOutput: number;
}

export class ArithmeticNeuralCircuit {
  /**
   * Encodes Neural Layer linear operation (W * x + b) into arithmetic circuit constraints
   */
  public static evaluateCircuit(weights: number[], input: number[], bias: number): number {
    if (weights.length !== input.length) {
      throw new Error('Vector dimension mismatch in Arithmetic Circuit.');
    }

    let dot = 0;
    for (let i = 0; i < weights.length; i++) {
      dot += weights[i] * input[i];
    }
    return dot + bias;
  }
}
