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
 * Class to represent the response for getting an entry from a map. It contains both the value
 * itself, as well as an inclusion proof for how that value fits into the map root hash.
 */
public class MapGetEntryResponse {
	private byte[] key;
	private VerifiableEntry value;
	private byte[][] auditPath;
	private int treeSize;

	/**
	 * Constructor.
	 * @param key the key for which this value is valid.
	 * @param value the value for this key.
	 * @param auditPath the inclusion proof for this value in the map for a given tree size.
	 * @param treeSize the tree size that the inclusion proof is valid for.
	 */
	public MapGetEntryResponse(byte[] key, VerifiableEntry value, byte[][] auditPath, int treeSize) {
		this.key = key;
		this.value = value;
		this.auditPath = auditPath;
		this.treeSize = treeSize;
	}

	/**
	 * The key in this map entry response.
	 * @return the key
	 */
	public byte[] getKey() {
		return this.key;
	}

	/**
	 * The value in this map entry response.
	 * @return the value
	 */
	public VerifiableEntry getValue() {
		return this.value;
	}

	/**
	 * The tree size that this map entry response is valid for.
	 * @return the tree size
	 */
	public int getTreeSize() {
		return this.treeSize;
	}

	/**
	 * The audit path that can be applied to the value to reach the root hash for the map at this tree size.
	 * @return the audit path - for a map this is always 256 values, null values indicate that the default leaf value for that index should be used.
	 */
	public byte[][] getAuditPath() {
		return this.auditPath;
	}

	/**
	 * Calculates the root hash based on the audit path, tree size, key and value.
	 * @return the calculated root hash. Callers should compare this against the root hash returned by {@link VerifiableMap#getTreeHead(int)}.
	 * @throws ContinusecException upon error
	 */
	private byte[] calculateRootHash() throws ContinusecException {
		boolean[] kp = Util.constructMapKeyPath(this.key);
		byte[] t = this.value.getLeafHash();
		for (int i = kp.length - 1; i >= 0; i--) {
			byte[] p = this.auditPath[i];
			if (p == null) {
				p = Util.DEFAULT_LEAF_VALUES[i+1];
			}
			if (kp[i]) {
				t = Util.nodeMerkleTreeHash(p, t);
			} else {
				t = Util.nodeMerkleTreeHash(t, p);
			}
		}
		return t;
	}

	/**
	 * For a given tree head, check to see if our proof can produce it for the same tree size.
	 * @param head the MapTreeHead to compare
	 * @throws VerificationFailedException if any aspect of verification fails.
	 */
	public void verify(MapTreeHead head) throws VerificationFailedException {
		if (this.getTreeSize() != head.getMutationLogTreeHead().getTreeSize()) {
			throw new VerificationFailedException();
		}

		byte[] calcedHash;
		try {
			calcedHash = this.calculateRootHash();
		} catch (ContinusecException e) {
			throw new VerificationFailedException(e);
		}

		if (!(Arrays.equals(calcedHash, head.getRootHash()))) {
			throw new VerificationFailedException();
		}
	}
}
