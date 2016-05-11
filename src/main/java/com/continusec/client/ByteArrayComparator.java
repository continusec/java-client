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

import java.util.Comparator;

/**
 * Comparator for byte arrays so that these can be sorted for dictionaries in {@link ObjectHash}.
 */
public class ByteArrayComparator implements Comparator<byte[]> {

	private static final ByteArrayComparator self = new ByteArrayComparator();

	private ByteArrayComparator() {}

	/**
	 * Get the singleton instance to use.
	 * @return singleton instance.
	 */
	public static ByteArrayComparator getInstance() {
		return self;
	}

	private static int signedByte(byte a) {
		if (a < 0) {
			return 256 + (int)a;
		} else {
			return a;
		}
	}

	/**
	 * Compare byte arrays and return "a - b".
	 * Note that bytes in Java are signed, so that by default 0xff &lt; 0x00, which
	 * is not what we want, and why we are implementing our own Comparator.
	 * @param a first byte array
	 * @param b second byte array, they should be equal length
	 * @return moral equivalent to "a - b", undefined if a and b are different lengths.
	 */
	public int compare(byte[] a, byte[] b) {
		for (int i = 0; i < a.length && i < b.length; i++) {
			int x = signedByte(a[i]) - signedByte(b[i]);
			if (x != 0) {
				return x;
			}
		}
		return a.length - b.length; // should always be equal anyway
	}
}