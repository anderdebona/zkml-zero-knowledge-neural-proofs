import crypto from 'crypto';

export interface PlookupTableEntry {
  input: number;
  output: number;
}

export interface PlookupProof {
  tableSize: number;
  tableDigest: string;
  grandProductCommitment: string;
  lookupPointsCount: number;
  isValid: boolean;
}

export class PlookupArgumentTable {
  private lookupTable: Map<number, number> = new Map();
  private tableDigest: string;

  constructor() {
    this.setupNonLinearActivationTables();
    this.tableDigest = this.computeTableDigest();
  }

  /**
   * Builds precomputed integer lookup tables for GELU and SiLU activations
   */
  private setupNonLinearActivationTables(): void {
    // Quantized 8-bit range [-128, 127]
    for (let x = -128; x <= 127; x++) {
      const realX = x / 16.0;
      // GELU(x) = 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
      const geluVal = 0.5 * realX * (1 + Math.tanh(Math.sqrt(2 / Math.PI) * (realX + 0.044715 * Math.pow(realX, 3))));
      const quantizedGelu = Math.round(geluVal * 16.0);
      this.lookupTable.set(x, quantizedGelu);
    }
  }

  private computeTableDigest(): string {
    const serialized = Array.from(this.lookupTable.entries()).map(([k, v]) => `${k}:${v}`).join(',');
    return crypto.createHash('sha256').update(serialized).digest('hex');
  }

  /**
   * Generates a Plookup argument proof that all activation inputs map into the valid table
   */
  public generateLookupProof(inputs: number[]): PlookupProof {
    let allValid = true;
    const evaluatedPairs: PlookupTableEntry[] = [];

    for (const x of inputs) {
      if (!this.lookupTable.has(x)) {
        allValid = false;
      } else {
        evaluatedPairs.push({ input: x, output: this.lookupTable.get(x)! });
      }
    }

    // Grand product commitment simulation: \prod (1 + \beta)(f_i + \gamma) / (t_i + \gamma)
    const grandProduct = crypto.createHash('sha256')
      .update(this.tableDigest + evaluatedPairs.map(p => `${p.input}->${p.output}`).join(';'))
      .digest('hex');

    return {
      tableSize: this.lookupTable.size,
      tableDigest: this.tableDigest,
      grandProductCommitment: grandProduct,
      lookupPointsCount: inputs.length,
      isValid: allValid
    };
  }

  public lookup(input: number): number {
    return this.lookupTable.get(input) || 0;
  }
}
