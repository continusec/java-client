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

import java.util.List;
import java.util.Map;

/**
 * Package private class to represent raw value returned by HTTP call to server.
 */
class ResponseData {
	/**
	 * The raw body data.
	 */
	protected byte[] data;

	/**
	 * A map of headers.
	 */
	protected Map<String,List<String>> headers;

	/**
	 * Constructor.
	 * @param data the raw body data.
	 * @param headers the header map.
	 */
	protected ResponseData(byte[] data, Map<String,List<String>> headers) {
		this.data = data;
		this.headers = headers;
	}
}
