/**
 * Witness generator for zkML proof circuits
 */
export interface WitnessAssignment {
  variableId: string;
  value: number;
  isPublic: boolean;
}

/**
 * Circuit witness for R1CS constraint system
 */
export interface CircuitWitness {
  assignments: WitnessAssignment[];
  numPublic: number;
  numPrivate: number;
  isSatisfied: boolean;
}

/**
 * Witness Generator — Produces valid variable assignments for arithmetic
 * circuits in the R1CS (Rank-1 Constraint System) format.
 *
 * In a zk-SNARK system:
 * ```
 *   Circuit C defines constraints: A·z ⊙ B·z = C·z
 *   Witness w = (public_inputs, private_inputs) satisfies C
 *   Prover uses w to generate proof π
 *   Verifier checks π without knowing private inputs
 * ```
 *
 * Reference: Ben-Sasson et al., "SNARKs for C" (IEEE S&P, 2013)
 */
export class WitnessGenerator {
  /**
   * Generates a witness for a linear computation z = W·x + b.
   */
  public static generateLinearWitness(
    weights: number[],
    inputs: number[],
    bias: number
  ): CircuitWitness {
    const assignments: WitnessAssignment[] = [];

    // Public inputs
    inputs.forEach((val, i) => {
      assignments.push({ variableId: `input_${i}`, value: val, isPublic: true });
    });

    // Private weights
    weights.forEach((val, i) => {
      assignments.push({ variableId: `weight_${i}`, value: val, isPublic: false });
    });

    // Intermediate products (multiplication gates)
    let sum = bias;
    weights.forEach((w, i) => {
      const product = w * inputs[i];
      assignments.push({ variableId: `mul_${i}`, value: product, isPublic: false });
      sum += product;
    });

    // Output (public)
    assignments.push({ variableId: 'output', value: sum, isPublic: true });
    assignments.push({ variableId: 'bias', value: bias, isPublic: true });

    const numPublic = assignments.filter((a) => a.isPublic).length;
    const numPrivate = assignments.filter((a) => !a.isPublic).length;

    // Verify constraint satisfaction
    const computedOutput = weights.reduce((s, w, i) => s + w * inputs[i], bias);
    const isSatisfied = computedOutput === sum;

    return { assignments, numPublic, numPrivate, isSatisfied };
  }
}
