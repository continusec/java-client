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
 * Interface to represent any object that a Merkle Tree Leaf can be calculated for.
 */
public interface MerkleTreeLeaf {
	/**
	 * Calculate the leaf hash for this object.
	 * @return the Merkle Tree leaf hash.
	 * @throws ContinusecException upon error
	 */
	public byte[] getLeafHash() throws ContinusecException;
}
