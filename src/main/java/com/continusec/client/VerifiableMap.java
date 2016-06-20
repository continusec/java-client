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
import com.google.gson.JsonParser;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

import java.io.UnsupportedEncodingException;

/**
 * Class to manage interactions with a Verifiable Map. Use {@link ContinusecClient#getVerifiableMap(String)} to instantiate:
 * <pre>{@code
 * ContinusecClient client = new ContinusecClient("your account number", "your secret key");
 * VerifiableMap map = client.getVerifiableMap("testmap");
 * }</pre>
 * <p>
 * Once we have a handle to the map, to create it before first use:
 * <pre>{@code
 * try {
 *	 map.create();
 * } catch (ObjectConflictException e) {
 *	 // map has already been created
 * }
 * }</pre>
 * <p>
 * To add entries to the map (calling each of these adds an entry to the mutation log):
 * <pre>{@code
 * map.set("foo".getBytes(), new RawDataEntry("bar".getBytes()));
 * map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
 * map.set("fiz1".getBytes(), new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
 * map.delete("foo".getBytes());
 * }</pre>
 * <p>
 * To block until a mutation has been sequenced in the mutation log (useful for testing):
 * <pre>{@code
 * AddEntryResponse ae = map.set("fiz4".getBytes(), new RawDataEntry("foz4".getBytes()));
 * LogTreeHead lth = map.getMutationLog().blockUntilPresent(aer);
 * }</pre>
 * <p>
 * To further block until a specific mutation has been sequenced in the mutation log, and reflected back into the map of equivalent size (useful for testing):
 * <pre>{@code
 * MapTreeHead mth = map.blockUntilSize(lth.getTreeSize());
 * }</pre>
 * <p>
 * To get the latest MapTreeState from a map, verify the consistency of the underlying mutation log, and inclusion in the tree head log:
 * <pre>{@code
 * MapTreeState prev = loadPrevState();
 * MapTreeState head = map.getVerifiedLatestMapState(prev);
 * if (head.getTreeSize() > prev.getTreeSize()) {
 *     savePrevState(head);
 * }
 * }</pre>
 * <p>
 * To get a value from the log, and prove its inclusion in the map root hash:
 * <pre>{@code
 * VerifiableEntry entry = map.getVerifiedValue("foo".getBytes(), head, RawDataEntryFactory.getInstance());
 * }</pre>
 */
public class VerifiableMap {
	private ContinusecClient client;
	private String path;

	/**
	 * Package private constructor. Use {@link ContinusecClient#getVerifiableMap(String)} to instantiate.
	 * @param client the client (used for requests) that this map belongs to
	 * @param path the relative path to the map.
	 */
	protected VerifiableMap(ContinusecClient client, String path) {
		this.client = client;
		this.path = path;
	}

	/**
	 * Get a pointer to the mutation log that underlies this verifiable map. Since the mutation log
	 * is managed by the map, it cannot be directly modified, however all read operations are supported.
	 * Note that mutations themselves are stored as {@link JsonEntry} format, so {@link JsonEntryFactory#getInstance()} should
	 * be used for entry retrieval.
	 * @return the mutation log.
	 */
	public VerifiableLog getMutationLog() {
		return new VerifiableLog(this.client, this.path + "/log/mutation");
	}

	/**
	 * Get a pointer to the tree head log that contains all map root hashes produced by this map. Since the tree head log
	 * is managed by the map, it cannot be directly modified, however all read operations are supported.
	 * Note that tree heaads themselves are stored as {@link JsonEntry} format, so {@link JsonEntryFactory#getInstance()} should
	 * be used for entry retrieval.
	 * @return the tree head log.
	 */
	public VerifiableLog getTreeHeadLog() {
		return new VerifiableLog(this.client, this.path + "/log/treehead");
	}

	/**
	 * Send API call to create this map. This should only be called once, and subsequent
	 * calls will cause an exception to be generated.
	 * @throws ContinusecException upon error
	 */
	public void create() throws ContinusecException {
		this.client.makeRequest("PUT", this.path, null, null);
	}

	/**
	 * Destroy will send an API call to delete this map - this operation removes it permanently,
	 * and renders the name unusable again within the same account, so please use with caution.
	 * @throws ContinusecException upon error
	 */
	public void destroy() throws ContinusecException {
		this.client.makeRequest("DELETE", this.path, null, null);
	}

	private static final byte[][] parseAuditPath(ResponseData rd) throws DecoderException {
		byte[][]auditPath = new byte[256][];
		// since we have no guarantees that the map is case insensitive, iterate through each header
		for (String k : rd.headers.keySet()) {
			if (k != null && k.toLowerCase().equals("x-verified-proof")) {
				for (String h : rd.headers.get(k)) {
					for (String p : h.split(",")) {
						String[] bits = p.split("/");
						if (bits.length == 2) {
							auditPath[Integer.parseInt(bits[0].trim())] = Hex.decodeHex(bits[1].trim().toCharArray());
						}
					}
				}
			}
		}
		return auditPath;
	}

	private static final int parseVerifiedTreeSize(ResponseData rd) {
		for (String k : rd.headers.keySet()) {
			if (k != null && k.toLowerCase().equals("x-verified-treesize")) {
				for (String h : rd.headers.get(k)) {
					return Integer.parseInt(h);
				}
			}
		}
		return -1;
	}

	/**
	 * For a given key, retrieve the value and inclusion proof, verify the proof, then return the value.
	 * @param key the key in the map.
	 * @param treeHead a map tree state as previously returned by {@link #getVerifiedMapState(MapTreeState,int)}
	 * @param f the factory that should be used to instantiate the VerifiableEntry. Typically one of {@link RawDataEntryFactory#getInstance()}, {@link JsonEntryFactory#getInstance()}, {@link RedactedJsonEntryFactory#getInstance()}.
	 * @return the VerifiableEntry (which may be empty).
	 * @throws ContinusecException upon error
	 */
	public VerifiableEntry getVerifiedValue(byte[] key, MapTreeState treeHead, VerifiableEntryFactory f) throws ContinusecException {
		MapGetEntryResponse resp = this.get(key, treeHead.getTreeSize(), f);
		resp.verify(treeHead.getMapTreeHead());
		return resp.getValue();
	}

	/**
	 * For a given key, return the value and inclusion proof for the given treeSize.
	 * @param key the key in the map.
	 * @param treeSize the tree size.
	 * @param f the factory that should be used to instantiate the VerifiableEntry. Typically one of {@link RawDataEntryFactory#getInstance()}, {@link JsonEntryFactory#getInstance()}, {@link RedactedJsonEntryFactory#getInstance()}.
	 * @return the value (which may be empty) and inclusion proof.
	 * @throws ContinusecException upon error
	 */
	public MapGetEntryResponse get(byte[] key, int treeSize, VerifiableEntryFactory f) throws ContinusecException {
		try {
			ResponseData rd = this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/key/h/" + Hex.encodeHexString(key) + f.getFormat(), null, null);
			return new MapGetEntryResponse(key, f.createFromBytes(rd.data), parseAuditPath(rd), parseVerifiedTreeSize(rd));
		} catch (DecoderException e) {
			throw new InternalErrorException();
		}
	}

	/**
	 * Set the value for a given key in the map. Calling this has the effect of adding a mutation to the
	 * mutation log for the map, which then reflects in the root hash for the map. This occurs asynchronously.
	 * @param key the key to set.
	 * @param e the entry to set to key to. Typically one of {@link RawDataEntry}, {@link JsonEntry} or {@link RedactableJsonEntry}.
	 * @return add entry response, which includes the Merkle Tree Leaf hash of the mutation log entry added.
	 * @throws ContinusecException upon error
	 */
	public AddEntryResponse set(byte[] key, UploadableEntry e) throws ContinusecException {
		try {
			JsonObject j = new JsonParser().parse(new String(this.client.makeRequest("PUT", this.path + "/key/h/" + Hex.encodeHexString(key) + e.getFormat(), e.getDataForUpload(), null).data, "UTF-8")).getAsJsonObject();
			return new AddEntryResponse(Base64.decodeBase64(j.get("leaf_hash").getAsString()));
		} catch (UnsupportedEncodingException e1) {
			throw new ContinusecException(e1);
		}
	}

	/**
	 * Set the value for a given key in the map, conditional on the previous leaf hash value.
	 * Calling this has the effect of adding a mutation to the
	 * mutation log for the map, which then reflects in the root hash for the map. This occurs asynchronously.
	 * @param key the key to set.
	 * @param e the entry to set to key to. Typically one of {@link RawDataEntry}, {@link JsonEntry} or {@link RedactableJsonEntry}.
	 * @return add entry response, which includes the Merkle Tree Leaf hash of the mutation log entry added.
	 * @throws ContinusecException upon error
	 */
	public AddEntryResponse update(byte[] key, UploadableEntry e, MerkleTreeLeaf previousLeafHash) throws ContinusecException {
		try {
			String[][] headers = {{"X-Previous-LeafHash", Hex.encodeHexString(previousLeafHash.getLeafHash())}};
			JsonObject j = new JsonParser().parse(new String(this.client.makeRequest("PUT", this.path + "/key/h/" + Hex.encodeHexString(key) + e.getFormat(), e.getDataForUpload(), headers).data, "UTF-8")).getAsJsonObject();
			return new AddEntryResponse(Base64.decodeBase64(j.get("leaf_hash").getAsString()));
		} catch (UnsupportedEncodingException e1) {
			throw new ContinusecException(e1);
		}
	}

	/**
	 * Delete the value for a given key from the map. Calling this has the effect of adding a mutation to the
	 * mutation log for the map, which then reflects in the root hash for the map. This occurs asynchronously.
	 * @param key the key to delete.
	 * @return add entry response, which includes the Merkle Tree Leaf hash of the mutation log entry added.
	 * @throws ContinusecException upon error
	 */
	public AddEntryResponse delete(byte[] key) throws ContinusecException {
		try {
			JsonObject j = new JsonParser().parse(new String(this.client.makeRequest("DELETE", this.path + "/key/h/" + Hex.encodeHexString(key), null, null).data, "UTF-8")).getAsJsonObject();
			return new AddEntryResponse(Base64.decodeBase64(j.get("leaf_hash").getAsString()));
		} catch (UnsupportedEncodingException e1) {
			throw new ContinusecException(e1);
		}
	}

	/**
	 * Get the tree hash for given tree size.
	 *
	 * @param treeSize the tree size to retrieve the hash for. Pass {@link ContinusecClient#HEAD} to get the
	 * latest tree size.
	 * @return the tree hash for the given size (includes the tree size actually used, if unknown before running the query).
	 * @throws ContinusecException upon error
	 */
	public MapTreeHead getTreeHead(int treeSize) throws ContinusecException {
		try {
			JsonObject e = new JsonParser().parse(new String(this.client.makeRequest("GET", this.path + "/tree/" + treeSize, null, null).data, "UTF-8")).getAsJsonObject();
			return new MapTreeHead(
				Base64.decodeBase64(e.get("map_hash").getAsString()),
				LogTreeHead.fromJsonObject(e.getAsJsonObject("mutation_log"))
			);
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * getVerifiedLatestMapState fetches the latest MapTreeState, verifies it is consistent with,
	 * and newer than, any previously passed state.
	 * @param prev previously held MapTreeState, may be null to skip consistency checks.
	 * @return the latest map state (which may be the same as passed in if none newer available).
	 * @throws ContinusecException upon error
	 */
	public MapTreeState getVerifiedLatestMapState(MapTreeState prev) throws ContinusecException {
		MapTreeState head = this.getVerifiedMapState(prev, ContinusecClient.HEAD);
		if (prev != null) {
			if (head.getTreeSize() <= prev.getTreeSize()) {
				return prev;
			}
		}
		return head;
	}

	/**
	 * getVerifiedMapState returns a wrapper for the MapTreeHead for a given tree size, along with
	 * a LogTreeHead for the TreeHeadLog that has been verified to contain this map tree head.
	 * The value returned by this will have been proven to be consistent with any passed prev value.
	 * Note that the TreeHeadLogTreeHead returned may differ between calls, even for the same treeSize,
	 * as all future LogTreeHeads can also be proven to contain the MapTreeHead.
	 *
	 * Typical clients that only need to access current data will instead use getVerifiedLatestMapState()
	 * @param prev previously held MapTreeState, may be null to skip consistency checks.
	 * @param treeSize the tree size to retrieve the hash for. Pass {@link ContinusecClient#HEAD} to get the
	 * latest tree size.
	 * @return the map state for the given size
	 * @throws ContinusecException upon error
	 */
	public MapTreeState getVerifiedMapState(MapTreeState prev, int treeSize) throws ContinusecException {
		if ((treeSize != 0) && (prev != null) && (prev.getTreeSize() == treeSize)) {
			return prev;
		}

		MapTreeHead mapHead = this.getTreeHead(treeSize);
		if (prev != null) {
			this.getMutationLog().verifyConsistency(prev.getMapTreeHead().getMutationLogTreeHead(), mapHead.getMutationLogTreeHead());
		}

		LogTreeHead prevThlth = null;
		if (prev != null) {
			prevThlth = prev.getTreeHeadLogTreeHead();
		}

		LogTreeHead thlth = this.getTreeHeadLog().getVerifiedLatestTreeHead(prevThlth);
		this.getTreeHeadLog().verifyInclusion(thlth, mapHead);

		return new MapTreeState(mapHead, thlth);
	}

	/**
	 * Block until the map has caught up to a certain size.
	 * This polls {@link #getTreeHead(int)} until
	 * such time as a new tree hash is produced that is of at least this size.
	 * This is intended for test use.
	 * @param treeSize the tree size that we should wait for.
	 * @return the first tree hash that is at least this size.
	 * @throws ContinusecException upon error
	 */
	public MapTreeHead blockUntilSize(int treeSize) throws ContinusecException {
		int lastHead = -1;
		double secsToSleep = 0;
		while (true) {
			MapTreeHead mth = this.getTreeHead(ContinusecClient.HEAD);
			if (mth.getTreeSize() > lastHead) {
				lastHead = mth.getTreeSize();
				if (lastHead >= treeSize) {
					return mth;
				}
				// since we got a new tree head, reset sleep time
				secsToSleep = 1.0;
			} else {
				// no luck, snooze a bit longer
				secsToSleep *= 2.0;
			}
			try {
				Thread.sleep((long) (secsToSleep * 1000));
			} catch (InterruptedException e) {
				throw new ContinusecException (e);
			}
		}
	}
}
