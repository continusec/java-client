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
 * Response from adding entries to a log/map.
 * Can be used in subsequent calls to {@link VerifiableLog#verifyInclusion(LogTreeHead, MerkleTreeLeaf)}.
 */
public class AddEntryResponse implements MerkleTreeLeaf {
	/**
	 * Leaf hash of the entry.
	 */
	protected byte[] mtlHash;

	/**
	 * Package private constructor. Use {@link VerifiableLog#add(UploadableEntry)} to instantiate.
	 * @param mtlHash leaf hash of the entry.
	 */
	protected AddEntryResponse(byte[] mtlHash) {
		this.mtlHash = mtlHash;
	}

	/**
	 * Get the leaf hash for this entry.
	 * @return the leaf hash for this entry.
	 */
	public byte[] getLeafHash() throws ContinusecException {
		return this.mtlHash;
	}
}