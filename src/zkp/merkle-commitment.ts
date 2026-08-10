import * as crypto from 'crypto';

/**
 * A single node in the Merkle tree
 */
export interface MerkleNode {
  hash: string;
  left?: MerkleNode;
  right?: MerkleNode;
  data?: string;
}

/**
 * Proof path for verifying membership of a leaf in the Merkle tree
 */
export interface MerkleProof {
  leafHash: string;
  root: string;
  path: Array<{ hash: string; direction: 'left' | 'right' }>;
  isValid: boolean;
}

/**
 * Merkle Tree Commitment Scheme for Zero-Knowledge ML Model Verification.
 *
 * Allows a model owner to commit to their neural network weights without
 * revealing them. The verifier can later check that specific weights were
 * used in inference by verifying Merkle inclusion proofs.
 *
 * Architecture:
 * ```
 *        Root Hash
 *       /         \
 *     H(01)      H(23)
 *    /    \      /    \
 *  H(w0) H(w1) H(w2) H(w3)
 * ```
 *
 * Properties:
 * - **Binding**: Cannot change committed weights without changing root
 * - **Hiding**: Root hash reveals nothing about individual weights
 * - **Efficient verification**: O(log n) proof size for n weights
 *
 * Reference: Merkle, R. (1988). "A Digital Signature Based on a Conventional Encryption Function"
 */
export class MerkleCommitmentScheme {
  private root: MerkleNode | null = null;
  private leaves: MerkleNode[] = [];

  /**
   * Hashes a value using SHA-256
   */
  private static hashValue(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex');
  }

  /**
   * Combines two hashes into a parent hash
   */
  private static hashPair(left: string, right: string): string {
    return MerkleCommitmentScheme.hashValue(left + right);
  }

  /**
   * Commits to an array of model weights by building a Merkle tree.
   * Returns the root hash (the commitment).
   */
  public commit(weights: number[]): string {
    // Create leaf nodes from weight values
    this.leaves = weights.map((w) => ({
      hash: MerkleCommitmentScheme.hashValue(`weight:${w}`),
      data: `weight:${w}`,
    }));

    // Pad to power of 2 for balanced tree
    while (this.leaves.length > 0 && (this.leaves.length & (this.leaves.length - 1)) !== 0) {
      this.leaves.push({
        hash: MerkleCommitmentScheme.hashValue('padding:0'),
        data: 'padding:0',
      });
    }

    // Build tree bottom-up
    let currentLevel = [...this.leaves];
    while (currentLevel.length > 1) {
      const nextLevel: MerkleNode[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        const left = currentLevel[i];
        const right = currentLevel[i + 1] || left;
        const parentHash = MerkleCommitmentScheme.hashPair(left.hash, right.hash);
        nextLevel.push({ hash: parentHash, left, right });
      }
      currentLevel = nextLevel;
    }

    this.root = currentLevel[0] || null;
    return this.root?.hash || '';
  }

  /**
   * Generates a Merkle inclusion proof for a specific weight index.
   * The proof allows verifying that a weight exists in the commitment
   * without revealing other weights.
   */
  public generateProof(weightIndex: number): MerkleProof {
    if (!this.root || weightIndex >= this.leaves.length) {
      return { leafHash: '', root: '', path: [], isValid: false };
    }

    const leafHash = this.leaves[weightIndex].hash;
    const path: Array<{ hash: string; direction: 'left' | 'right' }> = [];

    // Walk up the tree collecting sibling hashes
    let level = [...this.leaves];
    let idx = weightIndex;

    while (level.length > 1) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      if (siblingIdx < level.length) {
        path.push({
          hash: level[siblingIdx].hash,
          direction: idx % 2 === 0 ? 'right' : 'left',
        });
      }

      // Move to next level
      const nextLevel: MerkleNode[] = [];
      for (let i = 0; i < level.length; i += 2) {
        const left = level[i];
        const right = level[i + 1] || left;
        nextLevel.push({
          hash: MerkleCommitmentScheme.hashPair(left.hash, right.hash),
          left,
          right,
        });
      }
      level = nextLevel;
      idx = Math.floor(idx / 2);
    }

    return { leafHash, root: this.root.hash, path, isValid: true };
  }

  /**
   * Verifies a Merkle proof against a root commitment.
   * Returns true if the leaf is genuinely part of the committed tree.
   */
  public static verifyProof(proof: MerkleProof): boolean {
    if (!proof.isValid) return false;

    let currentHash = proof.leafHash;
    for (const step of proof.path) {
      if (step.direction === 'right') {
        currentHash = MerkleCommitmentScheme.hashPair(currentHash, step.hash);
      } else {
        currentHash = MerkleCommitmentScheme.hashPair(step.hash, currentHash);
      }
    }

    return currentHash === proof.root;
  }

  /**
   * Returns the root hash (commitment value).
   */
  public getRoot(): string {
    return this.root?.hash || '';
  }
}
