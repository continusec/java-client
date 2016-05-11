/*
   Copyright 2016 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package com.continusec.client;

/**
 * Class to represent proof of inclusion of an entry in a log.
 */
public class LogInclusionProof implements InclusionProof {
	private int treeSize;
	private byte[] mtlHash;
	private int leafIdx;
	private byte[][] auditPath;

	/**
	 * Create new LogInclusionProof.
	 *
	 * @param treeSize the tree size for which this proof is valid.
	 * @param mtlHash the Merkle Tree Leaf hash of the entry this proof is valid for.
	 * @param leafIdx the index of this entry in the log.
	 * @param auditPath the set of Merkle Tree nodes that apply to this entry in order to generate the root hash and prove inclusion.
	 */
	public LogInclusionProof(int treeSize, byte[] mtlHash, int leafIdx, byte[][] auditPath) {
		this.treeSize = treeSize;
		this.mtlHash = mtlHash;
		this.leafIdx = leafIdx;
		this.auditPath = auditPath;
	}

	/**
	 * Returns the tree size.
	 * @return the tree size.
	 */
	public int getTreeSize() {
		return this.treeSize;
	}

	/**
	 * Returns the leaf index.
	 * @return the leaf index.
	 */
	public int getLeafIndex() {
		return this.leafIdx;
	}

	/**
	 * Returns the audit path.
	 * @return the audit path for this proof.
	 */
	public byte[][] getAuditPath() {
		return this.auditPath;
	}

	/**
	 * Calculates the root hash based on the audit path, tree size, leaf index and Merkle Tree Hash.
	 * @return the calculated root hash. Callers should compare this against the root hash returned by {@link VerifiableLog#getTreeHead(int)}.
	 * @throws ContinusecException upon error
	 */
	public byte[] calculateRootHash() throws ContinusecException {
		if ((this.leafIdx >= this.treeSize) || (this.leafIdx < 0)) {
			throw new InvalidRangeException();
		}

		int fn = this.leafIdx;
		int sn = this.treeSize - 1;
		byte[] r = this.mtlHash;
		for (byte[] p : this.auditPath) {
			if ((fn == sn) || ((fn & 1) == 1)) {
				r = Util.nodeMerkleTreeHash(p, r);
				while (!((fn == 0) || ((fn & 1) == 1))) {
					fn >>= 1;
					sn >>= 1;
				}
			} else {
				r = Util.nodeMerkleTreeHash(r, p);
			}
			fn >>= 1;
			sn >>= 1;
		}

		if (sn != 0) {
			throw new InvalidRangeException();
		}

		return r;
	}
}
