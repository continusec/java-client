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

import java.util.Iterator;
import java.lang.Iterable;

/**
 * Class to allow iteration over log entries. See {@link VerifiableLog#getEntries(int, int, VerifiableEntryFactory)}.
 */
public class LogEntryIterable implements Iterable<VerifiableEntry> {
	private ContinusecClient client;
	private String path;
	private int beginIdx;
	private int endIdx;
	private VerifiableEntryFactory factory;

	/**
	 * Package private constructor.
	 * @param client the client the log belongs to.
	 * @param path the path of the log within the account.
	 * @param beginIdx the first item to retrieve.
	 * @param endIdx the last item to retrieve.
	 * @param factory the factory to produce the VerifiableEntries.
	 */
	protected LogEntryIterable(ContinusecClient client, String path, int beginIdx, int endIdx, VerifiableEntryFactory factory) {
		this.client = client;
		this.path = path;
		this.beginIdx = beginIdx;
		this.endIdx = endIdx;
		this.factory = factory;
	}

	/**
	 * Return a new iterator for the range specified this this iterable.
	 * @return the iterator
	 */
	public Iterator<VerifiableEntry> iterator() {
		return new LogEntryIterator(this.client, this.path, this.beginIdx, this.endIdx, this.factory);
	}
}