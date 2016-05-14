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
		inclProof.verify(head103);

		try {
			inclProof.verify(head);
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

		JsonEntry je = new JsonEntry("{    \"ssn\":  123.4500 ,   \"name\" :  \"adam\"}".getBytes());
		inclProof = log.getInclusionProof(head103, je);
		inclProof.verify(head103);

		VerifiableEntry redEnt = log.get(2, RedactedJsonEntryFactory.getInstance());
		String dd = new String(redEnt.getData());
		if (dd.indexOf("ssn") >= 0) {
			throw new RuntimeException();
		}
		if (dd.indexOf("adam") < 0) {
			throw new RuntimeException();
		}
		inclProof = log.getInclusionProof(head103, redEnt);
		inclProof.verify(head103);

		client = new ContinusecClient("7981306761429961588", "allseeing", "http://localhost:8080");
		log = client.verifiableLog("newtestlog");

		redEnt = log.get(2, RedactedJsonEntryFactory.getInstance());
		dd = new String(redEnt.getData());
		if (dd.indexOf("123.45") < 0) {
			throw new RuntimeException();
		}
		if (dd.indexOf("adam") < 0) {
			throw new RuntimeException();
		}
		inclProof = log.getInclusionProof(head103, redEnt);
		inclProof.verify(head103);

        VerifiableMap map = client.verifiableMap("nnewtestmap");
        try {
            map.getTreeHead(client.HEAD);
			throw new RuntimeException();
        } catch (ObjectNotFoundException e) {
            // good
        }

        map.create();
        try {
            map.create();
			throw new RuntimeException();
        } catch (ObjectConflictException e) {
            // good
        }

		map.set("foo".getBytes(), new RawDataEntry("foo".getBytes()));
		map.set("fiz".getBytes(), new JsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));
		AddEntryResponse waitResponse = map.set("foz".getBytes(), new RedactableJsonEntry("{\"name\":\"adam\",\"ssn\":123.45}".getBytes()));

        for (int i = 0; i < 100; i++) {
            map.set(("foo"+i).getBytes(), new RawDataEntry(("fooval"+i).getBytes()));
        }

        map.delete("foo".getBytes());
        map.delete("foodddd".getBytes());
        map.delete("foo27".getBytes());

        LogTreeHead mlHead = map.getMutationLog().blockUntilPresent(waitResponse);
        if (mlHead.getTreeSize() != 106) {
			throw new RuntimeException();
        }

        MapTreeHead mrHead = map.blockUntilSize(mlHead.getTreeSize());
        if (mrHead.getMutationLogTreeHead().getTreeSize() != 106) {
			throw new RuntimeException();
        }
        MapGetEntryResponse entryResp = map.get("foo".getBytes(), mrHead, RawDataEntryFactory.getInstance());
        entryResp.verify(mrHead);

        dd = new String(entryResp.getValue().getData());
        if (dd.length() > 0) {
			throw new RuntimeException();
        }

        entryResp = map.get("foo-29".getBytes(), mrHead, RawDataEntryFactory.getInstance());
        entryResp.verify(mrHead);

        dd = new String(entryResp.getValue().getData());
        if (dd.length() > 0) {
			throw new RuntimeException();
        }

        entryResp = map.get("foo29".getBytes(), mrHead, RawDataEntryFactory.getInstance());
        entryResp.verify(mrHead);

        dd = new String(entryResp.getValue().getData());
        if (!"fooval29".equals(dd)) {
			throw new RuntimeException();
        }
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