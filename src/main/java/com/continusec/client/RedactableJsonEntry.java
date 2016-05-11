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
 * Class to represent JSON data should be made Redactable by the server upon upload.
 * ie change all dictionary values to be nonce-value tuples and control access to fields
 * based on the API key used to make the request.
 */
public class RedactableJsonEntry implements UploadableEntry {

	private byte[] rawData;

	/**
	 * Create a new entry based on rawData JSON.
	 * @param rawData representing the JSON for this entry.
	 */
	public RedactableJsonEntry(byte[] rawData) {
		this.rawData = rawData;
	}

	/**
	 * Get the suffix that should be added to the PUT/POST request for this data format.
	 * @return the suffix
	 */
	public String getFormatSuffix() {
		return "/xjson/redactable";
	}

	/**
	 * Get the data that should be stored.
	 * @return the JSON data
	 * @throws ContinusecException upon error
	 */
	public byte[] getDataForUpload() throws ContinusecException {
		return this.rawData;
	}
}
