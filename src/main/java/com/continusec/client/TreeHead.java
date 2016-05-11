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

import java.util.Arrays;

/**
 * Abstract class to represent a tree hash of either a log or a map.
 */
public abstract class TreeHead {
	private int treeSize;
	private byte[] rootHash;

	/**
	 * Package private constructor, should be called by base class.
	 * @param treeSize the size for which this tree hash is valid.
	 * @param rootHash the root hash for this size.
	 */
	protected TreeHead(int treeSize, byte[] rootHash) {
		this.treeSize = treeSize;
		this.rootHash = rootHash;
	}

	/**
	 * Returns the tree size for this tree hash.
	 * @return the tree size for this tree hash.
	 */
	public int getTreeSize() {
		return this.treeSize;
	}

	/**
	 * Returns the root hash for this tree size.
	 * @return the root hash for this tree size.
	 */
	public byte[] getRootHash() {
		return this.rootHash;
	}

	/**
	 * For a given inclusion proof, use this to calculate the root hash
	 * and compare this against the root hash and tree size that we represent.
	 * @param proof the inclusion proof to check
	 * @throws VerificationFailedException if any aspect of verification fails.
	 */
	public void verifyInclusion(InclusionProof proof) throws VerificationFailedException {
		if (this.getTreeSize() != proof.getTreeSize()) {
			throw new VerificationFailedException();
		}

		byte[] calcedHash;
		try {
			calcedHash = proof.calculateRootHash();
		} catch (ContinusecException e) {
			throw new VerificationFailedException(e);
		}

		if (!(Arrays.equals(calcedHash, this.getRootHash()))) {
			throw new VerificationFailedException();
		}
	}
}
