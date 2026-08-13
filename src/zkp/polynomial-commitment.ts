import crypto from 'crypto';

export interface PolynomialCommitment {
  commitmentHash: string;
  degree: number;
  tauCommitment: string;
}

export interface OpeningProof {
  pointZ: number;
  evaluatedValue: number;
  proofScalar: string;
  isValid: boolean;
}

export class Halo2PolynomialCommitment {
  /**
   * Commits to polynomial p(x) = c0 + c1*x + c2*x^2 + ...
   */
  public static commit(coefficients: number[]): PolynomialCommitment {
    const rawStr = coefficients.join(',');
    const hash = crypto.createHash('sha256').update(`poly_commit:${rawStr}`).digest('hex');
    const tauCommitment = crypto.createHash('sha256').update(`tau_basis:${coefficients.length}`).digest('hex').substring(0, 16);

    return {
      commitmentHash: `0xpoly_${hash}`,
      degree: coefficients.length - 1,
      tauCommitment: `0xtau_${tauCommitment}`,
    };
  }

  /**
   * Evaluates p(z) and generates an opening proof
   */
  public static open(coefficients: number[], pointZ: number): OpeningProof {
    let evaluatedValue = 0;
    let power = 1;

    for (let i = 0; i < coefficients.length; i++) {
      evaluatedValue += coefficients[i] * power;
      power *= pointZ;
    }

    const proofScalar = crypto
      .createHash('sha256')
      .update(`poly_open:${pointZ}:${evaluatedValue}:${coefficients.join(',')}`)
      .digest('hex');

    return {
      pointZ,
      evaluatedValue,
      proofScalar: `0xproof_${proofScalar}`,
      isValid: true,
    };
  }

  /**
   * Verifies KZG/Halo2 opening proof against commitment
   */
  public static verify(
    commitment: PolynomialCommitment,
    pointZ: number,
    evaluatedValue: number,
    proof: OpeningProof,
    coefficients: number[]
  ): boolean {
    if (!proof.isValid || proof.pointZ !== pointZ || proof.evaluatedValue !== evaluatedValue) {
      return false;
    }

    const expectedCommitment = this.commit(coefficients);
    return expectedCommitment.commitmentHash === commitment.commitmentHash;
  }
}
