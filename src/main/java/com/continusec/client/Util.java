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

import org.apache.commons.codec.digest.DigestUtils;
import java.security.MessageDigest;

/**
 * Contains various static utility methods.
 */
public class Util {

	/**
	 * Default leaf values for every level in a verifiable map. See {@link #generateMapDefaultLeafValues()}.
	 */
	protected final static byte[][] DEFAULT_LEAF_VALUES = generateMapDefaultLeafValues();

	/**
	 * Private constructor to avoid construction!
	 */
	private Util() {}

	/**
	 * Calculate the Merkle Tree Node Hash for an existing left and right hash (HASH(chr(1) || l || r)).
	 * @param l the left node hash.
	 * @param r the right node hash.
	 * @return the node hash for the combination.
	 */
	public static final byte[] nodeMerkleTreeHash(byte[] l, byte[] r) {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 1);
		d.update(l);
		d.update(r);
		return d.digest();
	}

	/**
	 * Calculate the Merkle Tree Leaf Hash for an object (HASH(chr(0) || b)).
	 * @param b the input to the leaf hash
	 * @return the leaf hash.
	 */
	public static final byte[] leafMerkleTreeHash(byte[] b) {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 0);
		d.update(b);
		return d.digest();
	}

	/**
	 * Generate the set of 257 default values for every level in a sparse Merkle Tree.
	 * @return array of length 257 default values.
	 */
	public static final byte[][] generateMapDefaultLeafValues() {
		byte[][] rv = new byte[257][];
		rv[256] = leafMerkleTreeHash(new byte[0]);
		for (int i = 255; i >= 0; i--) {
			rv[i] = nodeMerkleTreeHash(rv[i+1], rv[i+1]);
		}
		return rv;
	}

	/**
	 * Create the path in a sparse merkle tree for a given key. ie a boolean array representing
	 * the big-endian index of the the hash of the key.
	 * @param key the key
	 * @return a length 256 array of booleans representing left (false) and right (true) path in the Sparse Merkle Tree.
	 */
	public static final boolean[] constructMapKeyPath(byte[] key) {
		byte[] h = DigestUtils.getSha256Digest().digest(key);
		boolean[] rv = new boolean[h.length * 8];
		for (int i = 0; i < h.length; i++) {
			for (int j = 0; j < 8; j++) {
				if (((h[i] >> j) & 1) == 1) {
					rv[(i<<3)+7-j] = true;
				}
			}
		}
		return rv;
	}

	/**
	 * Package private utility method to check if n is a power of 2 or not.
	 * @param n the number to check.
	 * @return true if and only if n is a power of 2.
	 */
	protected static final boolean isPow2(int n) {
		return calcK(n + 1) == n;
	}

	private static final int calcK(int n) {
		int k = 1;
		while ((k << 1) < n) {
			k <<= 1;
		}
		return k;
	}

}