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

import org.apache.commons.codec.digest.DigestUtils;
import java.security.MessageDigest;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.text.Normalizer;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Map;
import java.util.ArrayList;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

/**
 * Utility class for calculating the ObjectHash (https://github.com/benlaurie/objecthash)
 * for objects.
 */
public class ObjectHash {

	/**
	 * Prefix to indicate that this value should not be treated as a string, and instead
	 * the remainder of the string is the hex encoded hash to use.
	 */
	public static final String StandardRedactionPrefix = "***REDACTED*** Hash: ";

	/**
	 * Calculate the objecthash for a Gson JsonElement object, assuming no redaction.
	 * @param o the Gson JsonElement to calculated the objecthash for.
	 * @return the objecthash for this object
	 * @throws ContinusecException upon error
	 */
	public static final byte[] objectHash(JsonElement o) throws ContinusecException {
		return objectHashWithRedaction(o, null);
	}

	/**
	 * Calculate the objecthash for a Gson JsonElement object, assuming the standard redaction prefix ({@link #StandardRedactionPrefix}) is used.
	 * @param o the Gson JsonElement to calculated the objecthash for.
	 * @return the objecthash for this object
	 * @throws ContinusecException upon error
	 */
	public static final byte[] objectHashWithStdRedaction(JsonElement o) throws ContinusecException {
		return objectHashWithRedaction(o, StandardRedactionPrefix);
	}

	/**
	 * Calculate the objecthash for a Gson JsonElement object, with a custom redaction prefix string.
	 * @param o the Gson JsonElement to calculated the objecthash for.
	 * @param r the string to use as a prefix to indicate that a string should be treated as a redacted subobject.
	 * @return the objecthash for this object
	 * @throws ContinusecException upon error
	 */
	public static final byte[] objectHashWithRedaction(JsonElement o, String r) throws ContinusecException {
		if (o == null || o.isJsonNull()) {
			return hashNull();
		} else if (o.isJsonArray()) {
			return hashArray(o.getAsJsonArray(), r);
		} else if (o.isJsonObject()) {
			return hashObject(o.getAsJsonObject(), r);
		} else if (o.isJsonPrimitive()) {
			JsonPrimitive p = o.getAsJsonPrimitive();
			if (p.isBoolean()) {
				return hashBoolean(p.getAsBoolean());
			} else if (p.isNumber()) {
				return hashDouble(p.getAsDouble());
			} else if (p.isString()) {
				return hashString(p.getAsString(), r);
			} else {
				throw new InvalidObjectException();
			}
		} else {
			throw new InvalidObjectException();
		}
	}

	private static final byte[] hashNull() throws ContinusecException {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 'n');
		return d.digest();
	}

	private static final byte[] hashArray(JsonArray a, String r) throws ContinusecException {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 'l');
		for (JsonElement e : a) {
			d.update(objectHashWithRedaction(e, r));
		}
		return d.digest();
	}

	private static final byte[] hashObject(JsonObject o, String r) throws ContinusecException {
		ArrayList<byte[]> entries = new ArrayList<byte[]>();
		for (Map.Entry<String,JsonElement> e : o.entrySet()) {
			entries.add(ArrayUtils.addAll(
				hashString(e.getKey(), r),
				objectHashWithRedaction(e.getValue(), r)
			));
		}
		Collections.sort(entries, ByteArrayComparator.getInstance());

		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 'd');
		for (byte[] b : entries) {
			d.update(b);
		}
		return d.digest();
	}

	private static final byte[] hashBoolean(boolean b) throws ContinusecException {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 'b');
		if (b) {
			d.update((byte) '1');
		} else {
			d.update((byte) '0');
		}
		return d.digest();
	}

	private static final byte[] hashString(String s, String r) throws ContinusecException {
		if (r != null && s.startsWith(r)) {
			try {
				return Hex.decodeHex(s.substring(r.length()).toCharArray());
			} catch (DecoderException e) {
				throw new InvalidObjectException(e);
			}
		} else {
			try {
				MessageDigest d = DigestUtils.getSha256Digest();
				d.update((byte) 'u');
				d.update(Normalizer.normalize(s, Normalizer.Form.NFC).getBytes("UTF8"));
				return d.digest();
			} catch (UnsupportedEncodingException e) {
				throw new InvalidObjectException(e);
			}
		}
	}

	private static final byte[] hashDouble(double f) throws ContinusecException {
		MessageDigest d = DigestUtils.getSha256Digest();
		d.update((byte) 'f');
		if (f < 0) {
			d.update((byte) '-');
			f = -f;
		} else {
			d.update((byte) '+');
		}
		int e = 0;
		while (f > 1) {
			f /= 2.0;
			e++;
		}
		while (f < 0.5) {
			f *= 2.0;
			e--;
		}
		d.update(Integer.toString(e).getBytes());
		d.update((byte) ':');
		if ((f > 1) || (f <= 0.5)) {
			throw new InvalidObjectException();
		}
		for (int cnt = 0; (f != 0) && (cnt < 1000); cnt++) {
			if (f >= 1) {
				d.update((byte) '1');
				f -= 1.0;
			} else {
				d.update((byte) '0');
			}
			if (f >= 1) {
				throw new InvalidObjectException();
			}
			f *= 2.0;
		}
		if (f != 0) { // we went too long
			throw new InvalidObjectException();
		}
		return d.digest();
	}

	private static final JsonElement shedArray(JsonArray o, String r) throws ContinusecException {
		JsonArray rv = new JsonArray();
		for (JsonElement e : o) {
			rv.add(shedRedactable(e, r));
		}
		return rv;
	}

	private static final JsonElement shedObject(JsonObject o, String r) throws ContinusecException {
		JsonObject rv = new JsonObject();
		for (Map.Entry<String,JsonElement> e : o.entrySet()) {
			JsonElement v = e.getValue();
			if (v.isJsonArray()) {
				JsonArray a = v.getAsJsonArray();
				if (a.size() == 2) {
					rv.add(e.getKey(), shedRedactable(a.get(1), r));
				} else {
					throw new InvalidObjectException();
				}
			} else if (v.isJsonPrimitive()) {
				JsonPrimitive p = v.getAsJsonPrimitive();
				if (p.isString()) {
					if (p.getAsString().startsWith(r)) {
						// all good, but we shed it.
					} else {
						throw new InvalidObjectException();
					}
				} else {
					throw new InvalidObjectException();
				}
			} else {
				throw new InvalidObjectException();
			}
		}
		return rv;
	}

	/**
	 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
	 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
	 * and normal processing needs to be performed on it.
	 * @param o the Gson JsonElement that contains the redacted elements and nonce-tuples.
	 * @param r the redaction prefix that indicates if a string represents a redacted sub-object.
	 * @return a new cleaned up JsonElement
	 * @throws ContinusecException upon error
	 */
	public static final JsonElement shedRedactable(JsonElement o, String r) throws ContinusecException {
		if (o == null) {
			return null;
		} else if (o.isJsonArray()) {
			return shedArray(o.getAsJsonArray(), r);
		} else if (o.isJsonObject()) {
			return shedObject(o.getAsJsonObject(), r);
		} else {
			return o;
		}
	}

	/**
	 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
	 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
	 * and normal processing needs to be performed on it. This method uses the standard redaction prefix ({@link #StandardRedactionPrefix}.
	 * @param o the Gson JsonElement that contains the redacted elements and nonce-tuples.
	 * @return a new cleaned up JsonElement
	 * @throws ContinusecException upon error
	 */
	public static final JsonElement shedRedactableWithStdRedaction(JsonElement o) throws ContinusecException {
		return shedRedactable(o, StandardRedactionPrefix);
	}
}