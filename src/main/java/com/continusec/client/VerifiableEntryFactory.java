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
 * Interface for instantiation of VerifiableEntries from bytes.
 */
public interface VerifiableEntryFactory {
	/**
	 * Create a new VerifiableEntry given these bytes from the server.
	 * @param bytes the bytes returned by the server.
	 * @return the VerifiableEntry
	 */
	public VerifiableEntry createFromBytes(byte[] bytes);

	/**
	 * Returns the format suffix for use with the GET request.
	 * @return the format suffix for use with the GET request.
	 */
	public String getFormat();
}