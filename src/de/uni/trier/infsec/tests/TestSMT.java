package de.uni.trier.infsec.tests;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pki.PKIServerCore;
import de.uni.trier.infsec.functionalities.smt.SMT;
//import de.uni.trier.infsec.functionalities.smt.SMT.AgentProxy;
import de.uni.trier.infsec.functionalities.smt.SMT.AuthenticatedMessage;
//import de.uni.trier.infsec.functionalities.smt.SMT.Channel;
import de.uni.trier.infsec.functionalities.smt.SMT.PKIError;
import de.uni.trier.infsec.functionalities.smt.SMT.Receiver;
import de.uni.trier.infsec.functionalities.smt.SMT.SMTError;
import de.uni.trier.infsec.functionalities.smt.SMT.Sender;
import static de.uni.trier.infsec.functionalities.smt.SMT.registerSender;
import static de.uni.trier.infsec.functionalities.smt.SMT.registerReceiver;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.Utilities;

public class TestSMT extends TestCase {
	public static int TEST_ID1 = 42424242;
	public static int TEST_ID2 = 43434343;
	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };


	@Test
	public void testSMT() throws PKIError, NetworkError, Exception, SMTError {
		Process pr = null;
		String server="localhost";
		int testPort=7777;
		try {
			PKI.useLocalMode();
			//PKI.useRemoteMode();
			
			Sender sender01 = registerSender(TEST_ID1);
			Receiver receiver02 = registerReceiver(TEST_ID2);
			
			// AgentProxy p1 = SMT.register(TEST_ID1);
			// AgentProxy p2 = SMT.register(TEST_ID2);
			
			// p2 = SMT.agentFromBytes(SMT.agentToBytes(p2));
			// p1 = SMT.agentFromBytes(SMT.agentToBytes(p1));
			
			// p2.getMessage(7777); // Starts listening for messages
			
			// Channel c1 = p1.channelTo(TEST_ID2, "localhost", 7777);
			// c1.send(TEST_DATA);
			NetworkServer.listenForRequests(testPort);
			sender01.sendTo(TEST_DATA, TEST_ID2, "localhost", testPort);
			Thread.sleep(500);
			// AuthenticatedMessage msg = p2.getMessage(7777);
			AuthenticatedMessage msg = receiver02.getMessage(testPort);
			
			System.out.println("REC " + Utilities.byteArrayToHexString(msg.message));
			assertTrue("Received data is not equal to sent data", Utilities.arrayEqual(TEST_DATA, msg.message));
			
			boolean error = false;
			try {
				//SMT.register(TEST_ID2);
				registerSender(TEST_ID1); // 1:1 matching SenderObj:ID 
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not lead to an error", error);
			
			error = false;
			try {
				//SMT.register(TEST_ID1);
				registerReceiver(TEST_ID2); // 1:1 matching ReceiverObj:ID 
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not lead to an error", error);
			
			error = false;
			try {
				sender01.sendTo(TEST_DATA, TEST_ID2 + 1, "localhost", testPort);
			} catch (NetworkError e) {
				error = true;
			}
			assertTrue("Invalid request did not lead to an error", error);
			
		} finally {
			if (pr != null) {
				pr.destroy();
			}
		}
	}

	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
	}

}
