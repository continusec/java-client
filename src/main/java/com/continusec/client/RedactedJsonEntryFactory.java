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
 * Factory that produces {@link RedactedJsonEntry} instances upon request.
 */
public class RedactedJsonEntryFactory implements VerifiableEntryFactory {
	private static final RedactedJsonEntryFactory self = new RedactedJsonEntryFactory();

	private RedactedJsonEntryFactory() {}

	/**
	 * Instantiate a new entry from bytes as returned by server.
	 * @param bytes the bytes as returned by the server.
	 * @return the new entry.
	 */
	public VerifiableEntry createFromBytes(byte[] bytes) {
		return new RedactedJsonEntry(bytes);
	}

	/**
	 * Returns the suffix added to calls to GET /entry/xxx
	 * @return the suffix to add.
	 */
	public String getFormat() {
	    return "/xjson";
	}

	/**
	 * Get singleton instance.
	 * @return singleton instance
	 */
	public static VerifiableEntryFactory getInstance() {
		return self;
	}
}
