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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import org.apache.commons.codec.binary.Base64;


import java.io.UnsupportedEncodingException;

/**
 * Class for Tree Hash as returned for a log with a given size.
 */
public class LogTreeHead {

	private int treeSize;
	private byte[] rootHash;

	/**
	 * Constructor.
	 * @param treeSize the tree size the root hash is valid for.
	 * @param rootHash the root hash for the log of this tree size.
	 */
	public LogTreeHead(int treeSize, byte[] rootHash) {
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
	 * Create object from a Gson JsonObject.
	 * @param o the Gson object.
	 * @return the log tree hash.
	 */
	protected static LogTreeHead fromJsonObject(JsonObject o) {
		JsonElement e2 = o.get("tree_hash");
		if (e2.isJsonNull()) {
			return new LogTreeHead(
				o.get("tree_size").getAsInt(),
				null
			);
		} else {
			return new LogTreeHead(
				o.get("tree_size").getAsInt(),
				Base64.decodeBase64(e2.getAsString())
			);
		}
	}
}
