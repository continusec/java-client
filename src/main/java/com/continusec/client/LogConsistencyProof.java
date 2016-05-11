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

import java.util.Arrays;

/**
 * Class to represent the result of a call to {@link VerifiableLog#getConsistencyProof(LogTreeHead,LogTreeHead)}.
 */
public class LogConsistencyProof {
	private int firstSize;
	private int secondSize;
	private byte[][] auditPath;

	/**
	 * Creates a new LogConsistencyProof for given tree sizes and auditPath.
	 * @param firstSize the size of the first tree.
	 * @param secondSize the size of the second tree.
	 * @param auditPath the audit proof returned by the server.
	 */
	public LogConsistencyProof(int firstSize, int secondSize, byte[][] auditPath) {
		this.firstSize = firstSize;
		this.secondSize = secondSize;
		this.auditPath = auditPath;
	}

	/**
	 * Returns the size of the first tree.
	 * @return the size of the first tree.
	 */
	public int getFirstSize() {
		return this.firstSize;
	}

	/**
	 * Returns the size of the second tree.
	 * @return the size of the second tree.
	 */
	public int getSecondSize() {
		return this.secondSize;
	}

	/**
	 * Returns the audit path.
	 * @return the audit path.
	 */
	public byte[][] getAuditPath() {
		return this.auditPath;
	}

	/**
	 * Verify that the consistency proof stored in this object can produce both the LogTreeHeads passed to this method.
	 * i.e, verify the append-only nature of the log between first.getTreeSize() and second.getTreeSize().
	 * @param first the tree hash for the first tree size
	 * @param second the tree hash for the second tree size
	 * @throws ContinusecException (most commonly {@link VerificationFailedException}) if the verification fails for any reason.
	 */
	public void verifyConsistency(LogTreeHead first, LogTreeHead second) throws ContinusecException {
		if ((first.getTreeSize() != this.firstSize) || (second.getTreeSize() != this.secondSize)) {
			throw new VerificationFailedException();
		}
		if ((this.firstSize < 1) || (this.firstSize > this.secondSize)) {
			throw new VerificationFailedException();
		}

		byte[][] newProof;
		if (Util.isPow2(this.firstSize)) {
			newProof = new byte[this.auditPath.length+1][];
			newProof[0] = first.getRootHash();
			for (int i = 0; i < this.auditPath.length; i++) {
				newProof[i + 1] = this.auditPath[i];
			}
		} else {
			newProof = this.auditPath;
		}

		int fn = this.firstSize - 1;
		int sn = this.secondSize - 1;
		while ((fn & 1) == 1) {
			fn >>= 1;
			sn >>= 1;
		}

		if (newProof.length == 0) {
			throw new VerificationFailedException();
		}

		byte[] fr = newProof[0];
		byte[] sr = newProof[0];

		for (int i = 1; i < newProof.length; i++) {
			if (sn == 0) {
				throw new VerificationFailedException();
			}

			if ((fn == sn) || ((fn & 1) == 1)) {
				fr = Util.nodeMerkleTreeHash(newProof[i], fr);
				sr = Util.nodeMerkleTreeHash(newProof[i], sr);
				while (!((fn == 0) || ((fn & 1) == 1))) {
					fn >>= 1;
					sn >>= 1;
				}
			} else {
				sr = Util.nodeMerkleTreeHash(sr, newProof[i]);
			}
			fn >>= 1;
			sn >>= 1;
		}

		if (sn != 0) {
			throw new VerificationFailedException();
		}

		if (!(Arrays.equals(fr, first.getRootHash()))) {
			throw new VerificationFailedException();
		}

		if (!(Arrays.equals(sr, second.getRootHash()))) {
			throw new VerificationFailedException();
		}
	}
}
