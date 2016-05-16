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

import java.lang.Iterable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonArray;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

import java.io.UnsupportedEncodingException;

import java.util.Stack;
import java.util.Arrays;

/**
 * Class to interact with verifiable logs. Instantiate by callling {@link ContinusecClient#getVerifiableLog(String)} method:
 * <pre>{@code
 * ContinusecClient client = new ContinusecClient("your account number", "your secret key");
 * VerifiableLog log = client.getVerifiableLog("testlog");
 * }</pre>
 * <p>
 * Once we have a handle to the log, to create it before first use:
 * <pre>{@code
 * try {
 *	 log.create();
 * } catch (ObjectConflictException e) {
 *	 // log has already been created
 * }
 * }</pre>
 * <p>
 * To add different types of entries to an existing log:
 * <pre>{@code
 * ContinusecClient client = new ContinusecClient("your account number", "your secret key");
 * VerifiableLog log = client.getVerifiableLog("testlog");
 *
 * // Add raw data entry
 * log.add(new RawDataEntry("foo".getBytes()));
 *
 * // JsonEntry wrapper will store the full JSON, but calculate the leaf hash based on the ObjectHash.
 * log.add(new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
 *
 * // RedactibleJsonEntry adds redactible nonces to each value in each object.
 * log.add(new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
 * }</pre>
 * <p>
 * To block until a new entry is fully incorporated into the tree (useful during testing):
 * <pre>{@code
 * AddEntryResponse aer = log.add(new RawDataEntry("foo".getBytes()));
 * LogTreeHead ltr = log.blockUntilPresent(aer);
 * }</pre>
 * <p>
 * To get a fresh tree hash from the log, and compare it against a previously seen tree hash for consistency:
 * <pre>{@code
 * LogTreeHead prev = loadPreviousTreeHead();
 * LogTreeHead head = log.getVerifiedLatestTreeHead(prev);
 * if (head.getTreeSize() > prev.getTreeSize()) {
 *	 saveLatestTreeHead(head);
 * }
 * }</pre>
 * <p>
 * To prove that some data is present in the log, where no proof is supplied with the data (assumes {@code head} was fetched earlier):
 * <pre>{@code
 * log.verifyInclusion(head, new RawDataEntry("foo".getBytes()));
 * }</pre>
 * <p>
 * To prove that some data is present in the log, where the proof has already been supplied with the data (assumes {@code head} was fetched earlier):
 * <pre>{@code
 * // Prove that an item is in the log (proof is supplied):
 * LogInclusionProof proof = loadSuppliedProof();
 *
 * // Fetch applicable tree head, verify consistency with our supplied tree head, then verify inclusion of proof
 * LogTreeHead inclusionHead = log.verifySuppliedInclusionProof(head, proof);
 * // Anytime we get a new tree head, make sure we save it off.
 * if (inclusionHead.getTreeSize() > head.getTreeSize()) {
 *	 saveLatestTreeHead(head);
 * }
 * }</pre>
 * <p>
 * For auditors that wish to audit both the contents as well as the correct operation of the log (see {@link #verifyEntries(LogTreeHead,LogTreeHead,VerifiableEntryFactory,LogAuditor)} for more details):
 * <pre>{@code
 * LogTreeHead prev = loadPreviousTreeHead(); // null is correct for first run
 * LogTreeHead head = log.getVerifiedLatestTreeHead(prev);
 *
 * log.verifyEntries(prev, head, RawDataEntryFactory.getInstance(), new LogAuditor() {
 *	 public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
 *		 byte[] b = e.getData();
 *		 // audit actual contents of entry
 *	 }
 * });
 *
 * if (head.getTreeSize() > prev.getTreeSize()) {
 *	 saveLatestTreeHead(head);
 * }
 * }</pre>
 */
public class VerifiableLog {
	private ContinusecClient client;
	private String path;

	/**
	 * Package private constructor. Use  {@link ContinusecClient#getVerifiableLog(String)} to instantiate.
	 * @param client the client (used for requests) that this log belongs to
	 * @param path the relative path to the log.
	 */
	protected VerifiableLog(ContinusecClient client, String path) {
		this.client = client;
		this.path = path;
	}

	/**
	 * Send API call to create this log. This should only be called once, and subsequent
	 * calls will cause an exception to be generated.
	 * @throws ContinusecException upon error
	 */
	public void create() throws ContinusecException {
		this.client.makeRequest("PUT", this.path, null);
	}

	/**
	 * Send API call to add an entry to the log. Note the entry is added asynchronously, so while
	 * the library will return as soon as the server acknowledges receipt of entry, it may not be
	 * reflected in the tree hash (or inclusion proofs) until the server has sequenced the entry.
	 *
	 * @param e the entry to add, often {@link RawDataEntry}, {@link JsonEntry} or {@link RedactableJsonEntry}.
	 * @return add entry response, which includes the Merkle Tree Leaf hash of the entry added.
	 * @throws ContinusecException upon error
	 */
	public AddEntryResponse add(UploadableEntry e) throws ContinusecException {
		try {
			JsonObject j = new JsonParser().parse(new String(this.client.makeRequest("POST", this.path + "/entry" + e.getFormatSuffix(), e.getDataForUpload()).data, "UTF-8")).getAsJsonObject();
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
	public LogTreeHead getTreeHead(int treeSize) throws ContinusecException {
		try {
			JsonObject e = new JsonParser().parse(new String(this.client.makeRequest("GET", this.path + "/tree/" + treeSize, null).data, "UTF-8")).getAsJsonObject();
			return LogTreeHead.fromJsonObject(e);
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * Get the entry at the specified index.
	 *
	 * @param idx the index to retrieve (starts at zero).
	 * @param f the type of entry to return, usually one of {@link RawDataEntryFactory#getInstance()}, {@link JsonEntryFactory#getInstance()}, {@link RedactedJsonEntryFactory#getInstance()}.
	 * @return the entry requested.
	 * @throws ContinusecException upon error
	 */
	public VerifiableEntry get(int idx, VerifiableEntryFactory f) throws ContinusecException {
		return f.createFromBytes(this.client.makeRequest("GET", this.path + "/entry/" + idx + f.getFormat(), null).data);
	}

	/**
	 * Returns an iterator to efficiently fetch a contiguous set of entries. If for any
	 * reason not all entries are returned, the iterator will terminate early.
	 *
	 * @param beginIdx the first entry to return
	 * @param endIdx the last entry to return
	 * @param f the type of entry to return, usually one of {@link RawDataEntryFactory#getInstance()}, {@link JsonEntryFactory#getInstance()}, {@link RedactedJsonEntryFactory#getInstance()}.
	 * @return an iterable for the entries requested.
	 * @throws ContinusecException upon error
	 */
	public Iterable<VerifiableEntry> getEntries(int beginIdx, int endIdx, VerifiableEntryFactory f) throws ContinusecException {
		return new LogEntryIterable(this.client, this.path, beginIdx, endIdx, f);
	}

	/**
	 * Get an inclusion proof for a given item for a specific tree size. Most clients will commonly use {@link #verifyInclusion(LogTreeHead,MerkleTreeLeaf)} instead.
	 * @param treeSize the tree size for which the inclusion proof should be returned. This is usually as returned by {@link #getTreeHead(int)}.getTreeSize().
	 * @param leaf the entry for which the inclusion proof should be returned. Note that {@link AddEntryResponse} and {@link VerifiableEntry} both implement {@link MerkleTreeLeaf}.
	 * @return a log inclusion proof object that can be verified against a given tree hash.
	 * @throws ContinusecException upon error
	 */
	public LogInclusionProof getInclusionProof(int treeSize, MerkleTreeLeaf leaf) throws ContinusecException {
		try {
			byte[] mtlHash = leaf.getLeafHash();
			JsonObject e = new JsonParser().parse(new String(this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/inclusion/h/" + Hex.encodeHexString(mtlHash), null).data, "UTF-8")).getAsJsonObject();
			return new LogInclusionProof(e.getAsJsonPrimitive("tree_size").getAsInt(), mtlHash, e.get("leaf_index").getAsInt(), jsonArrayToAuditProof(e.getAsJsonArray("proof")));
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * Get an inclusion proof for a given item and verify it.
	 * @param treeHead the tree head for which the inclusion proof should be returned. This is usually as returned by {@link #getTreeHead(int)}.
	 * @param leaf the entry for which the inclusion proof should be returned. Note that {@link AddEntryResponse} and {@link VerifiableEntry} both implement {@link MerkleTreeLeaf}.
	 * @throws ContinusecException upon error
	 */
	public void verifyInclusion(LogTreeHead treeHead, MerkleTreeLeaf leaf) throws ContinusecException {
		LogInclusionProof proof = this.getInclusionProof(treeHead.getTreeSize(), leaf);
		proof.verify(treeHead);
	}

	/**
	 * Get an inclusion proof for a specified tree size and leaf index. This is not used by typical clients,
	 * however it can be useful for audit operations and debugging tools. Typical clients will use {@link #verifyInclusion(LogTreeHead,MerkleTreeLeaf)}.
	 * @param treeSize the tree size on which to base the proof.
	 * @param leafIndex the leaf index for which to retrieve the inclusion proof.
	 * @return a partially filled in LogInclusionProof (note it will not include the MerkleTreeLeaf hash for the item).
	 * @throws ContinusecException upon error
	 */
	public LogInclusionProof getInclusionProofByIndex(int treeSize, int leafIndex) throws ContinusecException {
		try {
			JsonObject e = new JsonParser().parse(new String(this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/inclusion/" + leafIndex, null).data, "UTF-8")).getAsJsonObject();
			return new LogInclusionProof(e.getAsJsonPrimitive("tree_size").getAsInt(), null, e.get("leaf_index").getAsInt(), jsonArrayToAuditProof(e.getAsJsonArray("proof")));
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	private static byte[][] jsonArrayToAuditProof(JsonArray a) {
		byte[][] auditPath = new byte[a.size()][];
		for (int i = 0; i < auditPath.length; i++) {
			auditPath[i] = Base64.decodeBase64(a.get(i).getAsString());
		}
		return auditPath;
	}

	/**
	 * verifyConsistency takes two tree heads, retrieves a consistency proof and then verifies it.
	 * The two tree heads may be in either order (even equal), but both must be greater than zero and non-nil.
	 * @param a one log tree head
	 * @param b another log tree head
	 * @throws ContinusecException upon error
	 */
	public void verifyConsistency(LogTreeHead a, LogTreeHead b) throws ContinusecException {
		if ((a.getTreeSize() <= 0) || (b.getTreeSize() <= 0)) {
			throw new InvalidRangeException();
		}

		if (a.getTreeSize() == b.getTreeSize()) {
			if (!Arrays.equals(a.getRootHash(), b.getRootHash())) {
				throw new VerificationFailedException();
			}

			return; // special case, both are equal
		}

		LogTreeHead first;
		LogTreeHead second;
		if (a.getTreeSize() < b.getTreeSize()) {
			first = a;
			second = b;
		} else {
			first = b;
			second = a;
		}

		LogConsistencyProof proof = this.getConsistencyProof(first.getTreeSize(), second.getTreeSize());
		proof.verify(first, second);
	}

	/**
	 * ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
	 * that demonstrate how the root hash is calculated for both the first and second tree sizes.
	 * @param firstSize the size of the first tree.
	 * @param secondSize the size of the second tree.
	 * @return a log consistency proof object that must be verified.
	 * @throws ContinusecException upon error
	 */
	public LogConsistencyProof getConsistencyProof(int firstSize, int secondSize) throws ContinusecException {
		try {
			JsonObject e = new JsonParser().parse(new String(this.client.makeRequest("GET", this.path + "/tree/" + secondSize + "/consistency/" + firstSize, null).data, "UTF-8")).getAsJsonObject();
			return new LogConsistencyProof(e.getAsJsonPrimitive("first_tree_size").getAsInt(), e.getAsJsonPrimitive("second_tree_size").getAsInt(), jsonArrayToAuditProof(e.getAsJsonArray("proof")));
		} catch (UnsupportedEncodingException e) {
			throw new ContinusecException(e);
		}
	}

	/**
	 * Block until the log is able to produce a LogTreeHead that includes the specified MerkleTreeLeaf.
	 * This polls {@link #getTreeHead(int)} and {@link #verifyInclusion(LogTreeHead, MerkleTreeLeaf)} until
	 * such time as a new tree hash is produced that includes the given MerkleTreeLeaf. Exponential back-off
	 * is used when no tree hash is available. This is intended for test use - the returned tree head is not verified for consistency.
	 * @param leaf the leaf we should block until included. Typically this is a {@link AddEntryResponse} as returned by {@link #add(UploadableEntry)}.
	 * @return the first tree hash that includes this leaf (proof is not verified).
	 * @throws ContinusecException upon error
	 */
	public LogTreeHead blockUntilPresent(MerkleTreeLeaf leaf) throws ContinusecException {
		int lastHead = -1;
		double secsToSleep = 0;
		while (true) {
			LogTreeHead lth = this.getTreeHead(ContinusecClient.HEAD);
			if (lth.getTreeSize() > lastHead) {
				lastHead = lth.getTreeSize();
				try {
					this.verifyInclusion(lth, leaf);
					return lth;
				} catch (InvalidRangeException e) {
					// not present yet, ignore
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

	/**
	 * getVerifiedLatestTreeHead calls getVerifiedTreeHead() with HEAD to fetch the latest tree head,
	 * and additionally verifies that it is newer than the previously passed tree head.
	 * For first use, pass null to skip consistency checking.
	 * @param prev a previously persisted log tree head
	 * @return a new tree head, which has been verified to be consistent with the past tree head, or if no newer one present, the same value as passed in.
	 * @throws ContinusecException upon error
	 */
	public LogTreeHead getVerifiedLatestTreeHead(LogTreeHead prev) throws ContinusecException {
		LogTreeHead head = this.getVerifiedTreeHead(prev, ContinusecClient.HEAD);
		if (prev != null) {
			if (head.getTreeSize() <= prev.getTreeSize()) {
				return prev;
			}
		}
		return head;
	}

	/**
	 * VerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it is consistent with
	 * a tree head earlier fetched and persisted. For first use, pass null for prev, which will
	 * bypass consistency proof checking. Tree size may be older or newer than the previous head value.
	 * @param prev a previously persisted log tree head
	 * @param treeSize the tree size to fetch
	 * @return a new tree head, which has been verified to be consistent with the past tree head, or if no newer one present, the same value as passed in.
	 * @throws ContinusecException upon error
	 */
	public LogTreeHead getVerifiedTreeHead(LogTreeHead prev, int treeSize) throws ContinusecException {
		// special case returning the value we already have
		if ((treeSize != 0) && (prev != null) && (prev.getTreeSize() == treeSize)) {
			return prev;
		}

		// Fetch latest from server
		LogTreeHead head = this.getTreeHead(treeSize);

		if (prev != null) {
			this.verifyConsistency(prev, head);
		}

		return head;
	}

	/**
	 * VerifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
	 * to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
	 * with any prior supplied LogTreeHead.  To avoid potentially masking client tree head storage issues,
	 * it is an error to pass null. For first use, pass {@link LogTreeHead#ZeroLogTreeHead}, which will
	 * bypass consistency proof checking.
	 * @param prev a previously persisted log tree head, or special value {@link LogTreeHead#ZeroLogTreeHead}
	 * @param proof an inclusion proof that may be for a different tree size than prev.getTreeSize()
	 * @return the verified (for consistency) LogTreeHead that was used for successful verification (of inclusion) of the supplied proof. This may be older than the LogTreeHead passed in.
	 * @throws ContinusecException upon error
	 */
	public LogTreeHead verifySuppliedInclusionProof(LogTreeHead prev, LogInclusionProof proof) throws ContinusecException {
		LogTreeHead headForInclProof = this.getVerifiedTreeHead(prev, proof.getTreeSize());
		proof.verify(headForInclProof);
		return headForInclProof;
	}

	/**
	 * Utility method for auditors that wish to audit the full content of a log, as well as the log operation.
	 * This method will retrieve all entries in batch from the log, and ensure that the root hash in head can be confirmed to accurately represent the contents
	 * of all of the log entries. If prev is not NULL, then additionally it is proven that the root hash in head is consistent with the root hash in prev.
	 * @param prev a previous LogTreeHead representing the set of entries that have been previously audited. To avoid potentially masking client tree head storage issues, it is an error to pass NULL. To indicate this is has not previously been audited, pass {@link LogTreeHead#ZeroLogTreeHead},
	 * @param head the LogTreeHead up to which we wish to audit the log. Upon successful completion the caller should persist this for a future iteration.
	 * @param auditor caller should implemented a LogAuditor which is called sequentially for each log entry as it is encountered.
	 * @param factory the factory to use for instantiating log entries. Typically this is one of {@link RawDataEntryFactory#getInstance()}, {@link JsonEntryFactory#getInstance()}, {@link RedactedJsonEntryFactory#getInstance()}.
	 * @throws ContinusecException upon error
	 */
	public void verifyEntries(LogTreeHead prev, LogTreeHead head, VerifiableEntryFactory factory, LogAuditor auditor) throws ContinusecException {
		if ((prev == null) || prev.getTreeSize() < head.getTreeSize()) {
			Stack<byte[]> merkleTreeStack = new Stack<byte[]>();
			if ((prev != null) && (prev.getTreeSize() > 0)) {
				LogInclusionProof p = this.getInclusionProofByIndex(prev.getTreeSize()+1, prev.getTreeSize());
				byte[] firstHash = null;
				for (byte[] b : p.getAuditPath()) {
					if (firstHash == null) {
						firstHash = b;
					} else {
						firstHash = Util.nodeMerkleTreeHash(b, firstHash);
					}
				}
				if (!(Arrays.equals(firstHash, prev.getRootHash()))) {
					throw new VerificationFailedException();
				}
				for (int i = p.getAuditPath().length - 1; i >= 0; i--) {
					merkleTreeStack.push(p.getAuditPath()[i]);
				}
			}

			int idx = (prev == null) ? 0 : prev.getTreeSize();
			try {
				for (VerifiableEntry e : this.getEntries(idx, head.getTreeSize(), factory)) {
					// do whatever content audit is desired on e
					auditor.auditLogEntry(idx, e);

					// update the merkle tree hash stack:
					merkleTreeStack.add(e.getLeafHash());
					for (int z = idx; (z & 1) == 1; z >>= 1) {
						byte[] right = merkleTreeStack.pop();
						byte[] left = merkleTreeStack.pop();
						merkleTreeStack.push(Util.nodeMerkleTreeHash(left, right));
					}
					idx++;
				}
			} catch (RuntimeException e2) {
				// since get entries iterator throws a runtime exception that wraps the real continusec exception...
				Throwable cause = e2.getCause();
				if (cause instanceof ContinusecException) {
					throw (ContinusecException) cause;
				} else {
					throw e2;
				}
			}

			if (idx != head.getTreeSize()) {
				throw new NotAllEntriesReturnedException();
			}

			byte[] headHash = merkleTreeStack.pop();
			while (!merkleTreeStack.empty()) {
				headHash = Util.nodeMerkleTreeHash(merkleTreeStack.pop(), headHash);
			}

			if (!(Arrays.equals(headHash, head.getRootHash()))) {
				throw new VerificationFailedException();
			}
		}
	}
}
