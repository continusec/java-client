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
import com.google.gson.JsonParser;

import java.io.UnsupportedEncodingException;

/**
 * Class to be used when entry MerkleTreeLeafs should be based on ObjectHash
 * rather than the JSON bytes directly. Since there is no canonical encoding for JSON,
 * it is useful to hash these objects in a more defined manner.
 */
public class JsonEntry implements VerifiableEntry, UploadableEntry {
	private JsonElement fullJson = null;

	private byte[] lh = null;
	private byte[] rawData;

	/**
	 * Create entry object based on raw JSON data.
	 * @param rawData the raw JSON data.
	 */
	public JsonEntry(byte[] rawData) {
		this.rawData = rawData;
	}

	/**
	 * Get the data that should be stored.
	 * @return the raw data
	 * @throws ContinusecException upon error
	 */
	public byte[] getDataForUpload() throws ContinusecException {
		return this.getData();
	}

	/**
	 * Get the data that should be stored.
	 * @return the raw data
	 * @throws ContinusecException upon error
	 */
	public byte[] getData() throws ContinusecException {
		return this.rawData;
	}

	/**
	 * Calculate the leaf hash for this entry.
	 * This uses the {#link ObjectHash} class to produce the hash that this then uses
	 * as input to the Merkle Tree Leaf.
	 * @return the Merkle Tree leaf hash for this entry.
	 * @throws ContinusecException upon error
	 */
	public byte[] getLeafHash() throws ContinusecException {
		if (this.lh == null) {
			try {
				this.lh = Util.leafMerkleTreeHash(ObjectHash.objectHashWithStdRedaction(new JsonParser().parse(new String(this.rawData, "UTF8"))));
			} catch (UnsupportedEncodingException e) {
				throw new InvalidObjectException(e);
			}
		}
		return this.lh;
	}

	/**
	 * Returns the format suffix needed for the internal POST to /entry.
	 * @return format suffix
	 */
	public String getFormatSuffix() {
		return "/xjson";
	}

}
