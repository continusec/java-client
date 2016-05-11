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
 * Indicates the verification of a proof has failed.
 */
public class VerificationFailedException extends ContinusecException {

	/**
	 * Wrap another exception.
	 * @param e the exception to wrap.
	 */
	public VerificationFailedException(Exception e) {
		super(e);
	}

	/**
	 * Create new exception.
	 */
	public VerificationFailedException() { super(); }
}