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
 * Common interface for inclusion proofs in both maps and logs.
 */
public interface InclusionProof {
	/**
	 * Calculates the root hash based on the value presented and audit path provided.
	 * @return the calculated root hash, that a verifying typically checks against a root hash provided by a getTreeHead() method.
	 * @throws ContinusecException upon error
	 */
	public byte[] calculateRootHash() throws ContinusecException;

	/**
	 * The tree size for which this inclusion proof is valid.
	 * @return the tree size for which this inclusion proof is valid.
	 */
	public int getTreeSize();
}
