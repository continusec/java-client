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
 * Interface for auditors that wish to iterate over entries in a log,
 * to audit both the log operations, and the correctness (or other, as defined by the auditor)
 * of the entries. See {@link VerifiableLog#auditLogEntries(LogTreeHead, LogTreeHead, VerifiableEntryFactory, LogAuditor)}.
 */
public interface LogAuditor {
	/**
	 * Called by {@link VerifiableLog#auditLogEntries(LogTreeHead, LogTreeHead, VerifiableEntryFactory, LogAuditor)} as each log entry is encountered.
	 * It is up to the auditor what to do with each entry. The caller is responsible for verifying correct operation of the log, the auditor is responsible
	 * for any decision about the contents of the entries.
	 * @param idx the index in the log of this entry.
	 * @param e the entry itself
	 * @throws ContinusecException the auditor should throw a {@link ContinusecException} (which can wrap other exceptions) to halt the audit.
	 */
	public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException;
}
