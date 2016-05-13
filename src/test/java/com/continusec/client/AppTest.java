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

import org.junit.Test;
import static org.junit.Assert.assertEquals;
import java.io.File;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.FileInputStream;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import org.apache.commons.codec.binary.Hex;
import java.util.Stack;
import java.util.Arrays;

/*
		// Initialize client
		ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6");

		// Get pointer to a log object
		VerifiableLog log = client.verifiableLog("mysecondlog");

		// Create it (only call this once per log!)
		log.create();

		// Populate entries
		log.add(new RawDataEntry("foo".getBytes()));

		// JsonEntry wrapper will store the full JSON, but calculate the leaf hash based on the ObjectHash.
		log.add(new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));

		// RedactibleJsonEntry adds redactible nonces to each value in each object.
		log.add(new RedactibleJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));

		// Typical client operations

		// Fetch a new signed tree head, and prove append-only nature of log
		LogTreeHash prev = new LogTreeHash(...load from storage...);
		LogTreeHash head = log.getTreeHash(ContinusecClient.HEAD);

		if (head.getTreeSize() > prev.getTreeSize()) {
			LogConsistencyProof p = log.getConsistencyProof(prev, head);
			p.verifyConsistency(prev, head);
			... write head to storage ...
		}

		// Prove that an item is in the log (no proof supplied):
		LogInclusionProof proof = log.getInclusionProof(head, new RawDataEntry("foo".getBytes()));
		head.verifyInclusion(proof);

		// Prove that an item is in the log (proof is supplied):
		LogInclusionProof proof = new LogInclusionProof(... supplied proof ...);

		// Get the tree head for size in the proof
		LogTreeHash inclusionHead = log.getTreeHash(proof.getTreeSize());

		// Ensure this root hash is consistent with the root hash we are tracking
		if (inclusionHead.getTreeSize() < head.getTreeSize()) { // it's older, verify consistency
			LogConsistencyProof p = log.getConsistencyProof(inclusionHead, head);
			p.verifyConsistency(inclusionHead, head);
		} else if (inclusionHead.getTreeSize() > head.getTreeSize()) { // it's new, verify consistency and store new head
			LogConsistencyProof p = log.getConsistencyProof(head, inclusionHead);
			p.verifyConsistency(head, inclusionHead);
			... write inclusionHead to storage ...
			head = inclusionHead;
		} else { // they are equal. use our existing head since we've validated the consistency of the root hash.
			inclusionHead = head;
		}

		// Now verify inclusion
		inclusionHead.verifyInclusion(proof);

		// Auditor operations
		LogTreeHash prev = new LogTreeHash(...load from storage...);
		LogTreeHash head = log.getTreeHash(ContinusecClient.HEAD);

		Util.auditLogEntries(log, prev, head, new LogAuditor() {
			public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
				// audit actual contents of entry
			}
		}, RawDataEntryFactory.getInstance());

		... write head to storage ...



		// Map operations
		ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6");

		// Get pointer to a map
		VerifiableMap map = client.verifiableMap("nextmap");

		// Create map - only do once
		map.create();

		// Populate
		map.set("foo".getBytes(), new RawDataEntry("bar".getBytes()));
		map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz1".getBytes(), new RedactibleJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz2".getBytes(), new RawDataEntry("foz2".getBytes()));
		map.set("fiz3".getBytes(), new RawDataEntry("foz3".getBytes()));
		AddEntryResponse rr = map.set("fiz4".getBytes(), new RawDataEntry("foz4".getBytes()));


		map.getMutationLog().blockUntilPresent(rr);

		// Get head
		MapTreeHash head = map.getTreeHash(ContinusecClient.HEAD);




		// Typical client:





		VerifiableMap map = client.verifiableMap("mysecondmap");

		// Only call create the first time
		map.create();

		// Populate
		map.set("foo".getBytes(), new RawDataEntry("bar".getBytes()));
		map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz1".getBytes(), new RedactibleJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz2".getBytes(),  new RawDataEntry("foz2".getBytes()));
		map.set("fiz3".getBytes(),  new RawDataEntry("foz3".getBytes()));
		map.set("fiz4".getBytes(),  new RawDataEntry("foz4".getBytes()));



*/




public class AppTest {
	@Test
	public void testContinusec() throws ContinusecException {
		ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", "http://localhost:8080");
		VerifiableLog log = client.verifiableLog("newtestlog");
		try {
			log.getTreeHead(client.HEAD);
			throw new RuntimeException();
		} catch (ObjectNotFoundException e) {
			// good
		}

		client = new ContinusecClient("7981306761429961588", "wrongcred", "http://localhost:8080");
		log = client.verifiableLog("newtestlog");
		try {
			log.getTreeHead(client.HEAD);
			throw new RuntimeException();
		} catch (UnauthorizedAccessException e) {
			// good
		}

		client = new ContinusecClient("wrongaccount", "wrongcred", "http://localhost:8080");
		log = client.verifiableLog("newtestlog");
		try {
			log.getTreeHead(client.HEAD);
			throw new RuntimeException();
		} catch (ObjectNotFoundException e) {
			// good
		}

		client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6", "http://localhost:8080");
		log = client.verifiableLog("newtestlog");
		log.create();

		try {
			log.create();
			throw new RuntimeException();
		} catch (ObjectConflictException e) {
			// good
		}

		log.add(new RawDataEntry("foo".getBytes()));
		log.add(new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		log.add(new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));

		AddEntryResponse aer = log.add(new RawDataEntry("foo".getBytes()));
		log.blockUntilPresent(aer);

		LogTreeHead head = log.getTreeHead(client.HEAD);
		if (head.getTreeSize() != 3) {
			throw new RuntimeException();
		}

		for (int i = 0; i < 100; i++) {
			log.add(new RawDataEntry(("foo-"+i).getBytes()));
		}

		LogTreeHead head103 = log.fetchVerifiedTreeHead(head);
		if (head103.getTreeSize() != 103) {
			throw new RuntimeException();
		}

		try {
			log.getInclusionProof(head103, new RawDataEntry(("foo27").getBytes()));
			throw new RuntimeException();
		} catch (ObjectNotFoundException e) {
			// good
		}

		LogInclusionProof inclProof = log.getInclusionProof(head103, new RawDataEntry(("foo-27").getBytes()));
		head103.verifyInclusion(inclProof);

		try {
			head.verifyInclusion(inclProof);
			throw new RuntimeException();
		} catch (VerificationFailedException e) {
			// good
		}

		LogTreeHead head50 = log.getTreeHead(50);
		if (head50.getTreeSize() != 50) {
			throw new RuntimeException();
		}

		LogConsistencyProof cons = log.getConsistencyProof(head50, head103);
		cons.verifyConsistency(head50, head103);

		try {
			cons.verifyConsistency(head, head103);
			throw new RuntimeException();
		} catch (VerificationFailedException e) {
			// good
		}

		inclProof = log.getInclusionProof(10, new RawDataEntry("foo".getBytes()));

		LogTreeHead h10 = log.verifySuppliedInclusionProof(head103, inclProof);
		if (h10.getTreeSize() != 10) {
			throw new RuntimeException();
		}


		final int[] count = new int[1];

		count[0] = 0;
		log.auditLogEntries(LogTreeHead.ZeroLogTreeHead, head103, RawDataEntryFactory.getInstance(), new LogAuditor() {
			public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
				e.getData();
				count[0]++;
			}
		});
		if (count[0] != 103) {
			throw new RuntimeException();
		}

		LogTreeHead head1 = log.getTreeHead(1);
		count[0] = 0;
		try {
			log.auditLogEntries(head1, head103, JsonEntryFactory.getInstance(), new LogAuditor() {
				public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
					e.getData();
					count[0]++;
				}
			});
			throw new RuntimeException();
		} catch (NotAllEntriesReturnedException e) {
			// good
		}
		if (count[0] != 0) {
			throw new RuntimeException();
		}

		LogTreeHead head3 = log.getTreeHead(3);
		count[0] = 0;
		log.auditLogEntries(head1, head3, JsonEntryFactory.getInstance(), new LogAuditor() {
			public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
				e.getData();
				count[0]++;
			}
		});
		if (count[0] != 2) {
			throw new RuntimeException();
		}

		count[0] = 0;
		log.auditLogEntries(head50, head103, RawDataEntryFactory.getInstance(), new LogAuditor() {
			public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
				e.getData();
				count[0]++;
			}
		});
		if (count[0] != 53) {
			throw new RuntimeException();
		}
		// Initialize client
	//	ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6");
/*
		// Get pointer to a log object
		VerifiableLog log = client.verifiableLog("my4log");

		// Create it (only call this once per log!)
		try {
			log.create();
		} catch (ObjectConflictException e) {
			System.out.println("Log already exists, ignoring");
		}

		// Populate entries
		log.add(new RawDataEntry("foo".getBytes()));

		// JsonEntry wrapper will store the full JSON, but calculate the leaf hash based on the ObjectHash.
		log.add(new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));

		// RedactibleJsonEntry adds redactible nonces to each value in each object.
		log.blockUntilPresent(log.add(new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes())));


		// Typical client operations

		// Fetch a new signed tree head, and prove append-only nature of log
		LogTreeHash prev = log.getTreeHash(1);
		LogTreeHash head = log.getTreeHash(ContinusecClient.HEAD);

		if (head.getTreeSize() > prev.getTreeSize()) {
			LogConsistencyProof p = log.getConsistencyProof(prev, head);
			p.verifyConsistency(prev, head);
		}

		// Prove that an item is in the log (no proof supplied):
		LogInclusionProof proof = log.getInclusionProof(head, new RawDataEntry("foo".getBytes()));
		head.verifyInclusion(proof);



		Util.auditLogEntries(log, prev, head, new LogAuditor() {
			public void auditLogEntry(int idx, VerifiableEntry e) throws ContinusecException {
				System.out.println(idx + " " + e);
			}
		}, RawDataEntryFactory.getInstance());



		// Map operations
		//ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6");

		// Get pointer to a map
		VerifiableMap map = client.verifiableMap("mythrismajjp1");

		// Create map - only do once
		try {
			map.create();
		} catch (ObjectConflictException e) {
			System.out.println("Map already exists, ignoring");
		}

		// Populate
		map.set("foo".getBytes(), new RawDataEntry("bar".getBytes()));
		map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz1".getBytes(), new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz2".getBytes(), new RawDataEntry("foz2".getBytes()));
		map.set("fiz3".getBytes(), new RawDataEntry("foz3".getBytes()));
		AddEntryResponse rr = map.set("fiz4".getBytes(), new RawDataEntry("foz4".getBytes()));

		map.getMutationLog().blockUntilPresent(rr);

		// Get head
		MapTreeHash mapHead = map.getTreeHash(ContinusecClient.HEAD);
		MapGetEntryResponse rrrr = map.get("foo".getBytes(), mapHead, RawDataEntryFactory.getInstance());
		mapHead.verifyInclusion(rrrr);

		MapGetEntryResponse rrrrs = map.get("foossss".getBytes(), mapHead, RawDataEntryFactory.getInstance());
		mapHead.verifyInclusion(rrrrs);
*/


	/*	// Initialize client
		ContinusecClient client = new ContinusecClient("7981306761429961588", "c9fc80d4e19ddbf01a4e6b5277a29e1bffa88fe047af9d0b9b36de536f85c2c6");
*/
	/*	VerifiableMap map = client.verifiableMap("hkhjkh");
		VerifiableLog treeHeadLog = map.getTreeHeadLog();
		VerifiableLog mutationLog = map.getMutationLog();

		MapTreeHash mth = map.getTreeHash(0);

		LogTreeHash thh = treeHeadLog.getTreeHash(0);
		thh.verifyInclusion(treeHeadLog.getInclusionProof(thh, mth));
		*/

		// Only call create the first time
		//map.create();

		// Populate
	/*	map.set("foo".getBytes(), new RawDataEntry("bar".getBytes()));
		map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz1".getBytes(), new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		map.set("fiz2".getBytes(), new RawDataEntry("foz2".getBytes()));
		map.set("fiz3".getBytes(), new RawDataEntry("foz3".getBytes()));*/
	//	AddEntryResponse rr = map.set("fiz4".getBytes(), new RawDataEntry("foz4".getBytes()));



		// Get head
	//	MapTreeHash head = map.blockUntilSize(map.getMutationLog().blockUntilPresent(rr).getTreeSize());
	//	System.out.println(head.getTreeSize());


		// Wait for map to sync, then later:


		// And get values and verify their inclusion in head
		//MapGetEntryResponse<RawDataEntry> entry = map.get("foo".getBytes(), head.getTreeSize());
		//System.out.println(new String(entry.getValue().getData()));
	    //Util.verifyMapInclusionProof(entry, head);

		//MapGetEntryResponse<JsonEntry> e1 = map.getJson("fiz".getBytes(), head.getTreeSize());
		//System.out.println(new String(e1.getValue().getData()));
	    //Util.verifyMapInclusionProof(e1, head);

		//MapGetEntryResponse<RedactedJsonEntry> e2 = map.getRedactedJson("fiz1".getBytes(), head.getTreeSize());
		//System.out.println(new String(e2.getValue().getData()));
	    //Util.verifyMapInclusionProof(e2, head);
	}

	private static final void runCommonJsonTests(String path) throws Exception {
		BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(path))));
		String line = null;
		int state = 0;
		String j = null;
		while ((line = reader.readLine()) != null) {
			line = line.trim();
			if (line.length() > 0 && !line.startsWith("#")) {
				if (state == 0) {
					j = line;
					state = 1;
				} else if (state == 1) {
					if (new String(Hex.encodeHex(ObjectHash.objectHashWithStdRedaction(new JsonParser().parse(j)))).toLowerCase().equals(line.toLowerCase())) {
						System.out.println("Match! - " + j + " " + line);
					} else {
						System.out.println("Fail! - " + j + " " + line);
						throw new RuntimeException("fail");
					}
					state = 0;
				}
			}
		}
	}

	@Test
	public void testObjectHash() throws Exception {
		//runCommonJsonTests("../../objecthash/common_json.test");
	}
}