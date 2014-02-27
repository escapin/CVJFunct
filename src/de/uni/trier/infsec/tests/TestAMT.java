package de.uni.trier.infsec.tests;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.amt.AMT;
import de.uni.trier.infsec.functionalities.amt.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.AMT.RegistrationError;
import de.uni.trier.infsec.functionalities.amt.AMT.AuthenticatedMessage;
import de.uni.trier.infsec.functionalities.amt.AMT.Sender;
import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pki.PKIServerCore;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;


public class TestAMT extends TestCase {
	public static int TEST_ID1 = 42424242;
	public static int TEST_ID2 = 43434343;
	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };


	@Test
	public void testAMT() throws RegistrationError, NetworkError, Exception, AMTError {
		String server="localhost";
		int port=7777;
		
		PKI.useLocalMode();
		
		Sender sender = AMT.registerSender(TEST_ID1);
		sender = AMT.senderFromBytes(AMT.senderToBytes(sender));
		
		
		AMT.listenOn(port); // Starts listening for messages

		
		sender.sendTo(TEST_DATA, TEST_ID2, server, port);
		Thread.sleep(500);
		AuthenticatedMessage msg = AMT.getMessage(TEST_ID2, port);
		
		System.out.println("REC " + Utilities.byteArrayToHexString(msg.message));
		assertTrue("Received data is not equal to sent data", Utilities.arrayEqual(TEST_DATA, msg.message));
		
		boolean error = false;
		try {
			AMT.registerSender(TEST_ID1);
		} catch (RegistrationError e) {
			error = true;
		}
		assertTrue("Duplicate registration did not lead to an error", error);
	}

	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
	}

}
