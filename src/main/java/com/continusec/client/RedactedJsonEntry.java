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
 * Class to represent redacted entries as returned by the server. Not to be confused
 * with {@link RedactableJsonEntry} that should be used to represent objects that should
 * be made Redactable by the server when uploaded.
 */
public class RedactedJsonEntry implements VerifiableEntry {
	private byte[] shedData = null;
	private byte[] lh = null;
	private byte[] rawData;

	/**
	 * Package private constructor. Unlike the other Entry types, this is made package
	 * private deliberately to prevent accidental confusion with {@link RedactableJsonEntry}
	 * which is what should be used to create an entry for upload.
	 * @param rawData the raw data respresenting the redacted JSON.
	 */
	protected RedactedJsonEntry(byte[] rawData) {
		this.rawData = rawData;
	}

	/**
	 * Get the underlying JSON for this entry, with all Redactable nonce-tuples and
	 * redacted sub-objects stripped for ease of processing. See {@link ObjectHash#shedRedactableWithStdRedaction(JsonElement)}.
	 * @return the JSON with with Redactable artefacts shed.
	 * @throws ContinusecException upon error
	 */
	public byte[] getData() throws ContinusecException {
		if (this.shedData == null) {
			try {
				this.shedData = ObjectHash.shedRedactableWithStdRedaction(new JsonParser().parse(new String(this.rawData, "UTF8"))).toString().getBytes("UTF8");
			} catch (UnsupportedEncodingException e) {
				throw new InvalidObjectException(e);
			}
		}
		return this.shedData;
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
			if (this.rawData.length == 0) {
				this.lh = Util.leafMerkleTreeHash(this.rawData);
			} else {
				try {
					this.lh = Util.leafMerkleTreeHash(ObjectHash.objectHashWithStdRedaction(new JsonParser().parse(new String(this.rawData, "UTF8"))));
				} catch (UnsupportedEncodingException e) {
					throw new InvalidObjectException(e);
				}
			}
		}
		return this.lh;
	}
}
