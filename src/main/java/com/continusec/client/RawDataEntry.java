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
 * Class to represent a log/map entry where no special processing is performed,
 * that is, the bytes specified are stored as-is, and are used as-is for input
 * to the Merkle Tree leaf function.
 */
public class RawDataEntry implements VerifiableEntry, UploadableEntry {

	private byte[] rawData;
	private byte[] lh = null;

	/**
	 * Construct a new RawDataEntry with the specified rawData.
	 * @param rawData the raw data.
	 */
	public RawDataEntry(byte[] rawData) {
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
	 * @return the Merkle Tree leaf hash for this entry.
	 * @throws ContinusecException upon error
	 */
	public byte[] getLeafHash() throws ContinusecException {
		if (this.lh == null) {
			this.lh = Util.leafMerkleTreeHash(this.rawData);
		}
		return this.lh;
	}

	/**
	 * Get the suffix that should be added to the PUT/POST request for this data format.
	 * @return the suffix
	 */
	public String getFormatSuffix() {
		return "";
	}

}