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

import com.google.gson.JsonObject;
import org.apache.commons.codec.binary.Base64;



/**
 * Class for Tree Hash as returned for a map with a given size.
 */
public class MapTreeHead extends TreeHead implements MerkleTreeLeaf {

	private LogTreeHead mutationLogHash;
	private byte[] oh = null;

	/**
	 * Constructor.
	 * @param rootHash the root hash for the map of this tree size.
	 * @param mutationLogHash the corresponding tree hash for the mutation log
	 */
	public MapTreeHead(byte[] rootHash, LogTreeHead mutationLogHash) {
		super(mutationLogHash.getTreeSize(), rootHash);
		this.mutationLogHash = mutationLogHash;
	}

	/**
	 * Get corresponding the mutation log tree hash.
	 * @return the mutation log tree hash.
	 */
	public LogTreeHead getMutationLogTreeHead() {
		return this.mutationLogHash;
	}

	/**
	 * Implementation of getLeafHash() so that MapTreeHead can be used easily with
	 * {@link VerifiableLog#verifyInclusion(LogTreeHead, MerkleTreeLeaf)}.
	 * @return leaf hash base on the Object Hash for this map root hash with corresponding mutation log.
	 * @throws ContinusecException upon error
	 */
	public byte[] getLeafHash() throws ContinusecException {
		if (this.oh == null) {
			JsonObject ml = new JsonObject();
			ml.addProperty("tree_size", this.getMutationLogTreeHead().getTreeSize());
			ml.addProperty("tree_hash", Base64.encodeBase64String(this.getMutationLogTreeHead().getRootHash()));

			JsonObject mapo = new JsonObject();
			mapo.addProperty("map_hash", Base64.encodeBase64String(this.getRootHash()));
			mapo.add("mutation_log", ml);

			this.oh = Util.leafMerkleTreeHash(ObjectHash.objectHash(mapo));
		}
		return this.oh;
	}

}
