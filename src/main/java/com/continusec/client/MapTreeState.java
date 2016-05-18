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
 * Class for MapTreeState as returned by {@link VerifiableMap#getVerifiedMapState(MapTreeState,int)}.
 */
public class MapTreeState {

	private MapTreeHead mapTreeHead;
	private LogTreeHead treeHeadLogTreeHead;

	/**
	 * Constructor.
	 * @param treeHeadLogTreeHead the tree head for the underlying tree head log that the mapTreeHead has been verified as being included.
	 * @param mapTreeHead the map tree head for the map
	 */
	public MapTreeState(MapTreeHead mapTreeHead, LogTreeHead treeHeadLogTreeHead) {
		this.mapTreeHead = mapTreeHead;
		this.treeHeadLogTreeHead = treeHeadLogTreeHead;
	}

	/**
	 * Get corresponding the tree head log tree head.
	 * @return the tree head log tree head.
	 */
	public LogTreeHead getTreeHeadLogTreeHead() {
		return this.treeHeadLogTreeHead;
	}

	/**
	 * Get the map tree head.
	 * @return the map tree head
	 */
	public MapTreeHead getMapTreeHead() {
		return this.mapTreeHead;
	}

	/**
	 * Utility method for returning the size of the map that this state represents.
	 * @return the size
	 */
	public int getTreeSize() {
		return this.mapTreeHead.getTreeSize();
	}
}
