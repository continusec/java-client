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
import com.google.gson.JsonArray;
import com.google.gson.JsonParser;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.DecoderException;

import java.io.UnsupportedEncodingException;

import java.util.Iterator;

/**
 * An iterator for log entries.
 */
public class LogEntryIterator implements Iterator<VerifiableEntry> {
	private ContinusecClient client;
	private String path;
	private int beginIdx;
	private int endIdx;
	private int cursor;

	private JsonArray curArray;
	private int idxInArray;

	private VerifiableEntryFactory factory;

	private final static int BATCH = 500;

	/**
	 * Package private constructor.
	 * @param client the client the log belongs to.
	 * @param path the path of the log within the account.
	 * @param beginIdx the first item to retrieve.
	 * @param endIdx the last item to retrieve.
	 * @param factory the factory to produce the VerifiableEntries.
	 */
	protected LogEntryIterator(ContinusecClient client, String path, int beginIdx, int endIdx, VerifiableEntryFactory factory) {
		this.client = client;
		this.path = path;
		this.beginIdx = beginIdx;
		this.endIdx = endIdx;
		this.cursor = beginIdx;
		this.factory = factory;
	}

	/**
	 * Are there any more items?
	 * @return true if we haven't yet returned all items.
	 */
	public boolean hasNext() {
		return this.cursor < this.endIdx;
	}

	/**
	 * Get the next entry - will read from the server in large batches.
	 * @return the next entry.
	 */
	public VerifiableEntry next() {
		try {
			if ((curArray == null) || (this.idxInArray >= this.curArray.size())) {
				int tentLast = this.cursor + BATCH;
				if (tentLast > this.endIdx) {
					tentLast = this.endIdx;
				}
				String url = this.path + "/entries/" + this.cursor + "-" + tentLast + factory.getFormat();
				String s = new String(this.client.makeRequest("GET", url, null).data, "UTF-8");
				this.curArray =  new JsonParser().parse(s).getAsJsonObject().getAsJsonArray("entries");
				this.idxInArray = 0;
			}

			if (this.idxInArray < this.curArray.size()) {
				byte[] rv = Base64.decodeBase64(this.curArray.get(this.idxInArray).getAsJsonObject().get("leaf_data").getAsString());

				this.idxInArray += 1;
				this.cursor += 1;

				return factory.createFromBytes(rv);
			} else {
				throw new RuntimeException(new NotAllEntriesReturnedException());
			}
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(new InternalErrorException(e));
		} catch (ContinusecException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Unsupported operation (we are append-only!).
	 */
	public void remove() {
		throw new UnsupportedOperationException();
	}
}