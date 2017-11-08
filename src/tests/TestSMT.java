package tests;

import static funct.smt.SMT.registerReceiver;
import static funct.smt.SMT.registerSender;

import java.io.File;

import junit.framework.TestCase;
import utils.Utilities;

import org.junit.Test;

import funct.pki.PKI;
import funct.pki.PKIServerCore;
import funct.smt.SMT;
import funct.smt.SMT.AuthenticatedMessage;
import funct.smt.SMT.ConnectionError;
import funct.smt.SMT.Receiver;
import funct.smt.SMT.RegistrationError;
import funct.smt.SMT.SMTError;
import funct.smt.SMT.Sender;

public class TestSMT extends TestCase {
	public static int TEST_ID1 = 42424242;
	public static int TEST_ID2 = 43434343;
	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };


	@Test
	public void testSMT() throws RegistrationError, ConnectionError, Exception, SMTError {
		Process pr = null;
		String server="localhost";
		int port=7777;
		try {
			PKI.useLocalMode();
			// PKI.useRemoteMode(); // you'd need to start also PKIServerApp
			
			
			Sender sender01 = registerSender(TEST_ID1);
			Receiver receiver02 = registerReceiver(TEST_ID2);
			
			sender01 = SMT.senderFromBytes(SMT.senderToBytes(sender01));
			receiver02 = SMT.receiverFromBytes(SMT.receiverToBytes(receiver02));
			
			receiver02.listenOn(port); // Starts listening for messages
			
			sender01.sendTo(TEST_DATA, TEST_ID2, server, port);
			Thread.sleep(500);
			AuthenticatedMessage msg = receiver02.getMessage(port);
			
			System.out.println("REC " + Utilities.byteArrayToHexString(msg.message));
			assertTrue("Received data is not equal to sent data", Utilities.arrayEqual(TEST_DATA, msg.message));
			
			boolean error = false;
			try {
				//SMT.register(TEST_ID2);
				registerSender(TEST_ID1); // 1:1 matching SenderObj:ID 
			} catch (RegistrationError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not lead to an error", error);
			
			error = false;
			try {
				//SMT.register(TEST_ID1);
				registerReceiver(TEST_ID2); // 1:1 matching ReceiverObj:ID 
			} catch (RegistrationError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not lead to an error", error);
			
			error = false;
			try {
				sender01.sendTo(TEST_DATA, TEST_ID2, server, port + 1);
				//FIXME: this is not a fixme. At this point you should have a the stack traced of a 
				// NetworkError printed because the port is incorrect
			} catch (ConnectionError e) {
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
