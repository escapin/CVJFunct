package de.uni.trier.infsec.tests;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.amt.AMT;
import de.uni.trier.infsec.functionalities.amt.AMT.AMTError;
import de.uni.trier.infsec.functionalities.amt.AMT.PKIError;
import de.uni.trier.infsec.functionalities.amt.AMT.AgentProxy;
import de.uni.trier.infsec.functionalities.amt.AMT.AuthenticatedMessage;
import de.uni.trier.infsec.functionalities.amt.AMT.Channel;
import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pki.PKIServerCore;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class TestAMT extends TestCase {
	public static int TEST_ID1 = 42424242;
	public static int TEST_ID2 = 43434343;
	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };


	@Test
	public void testAMT() throws PKIError, NetworkError, Exception, AMTError {
		PKI.useLocalMode();

		AgentProxy p1 = AMT.register(TEST_ID1);
		AgentProxy p2 = AMT.register(TEST_ID2);
		
		p2 = AMT.agentFromBytes(AMT.agentToBytes(p2));
		p1 = AMT.agentFromBytes(AMT.agentToBytes(p1));
		
		p2.getMessage(7777); // Starts listening for messages
		
		Channel c1 = p1.channelTo(TEST_ID2, "localhost", 7777);
		c1.send(TEST_DATA);
		Thread.sleep(5000);
		AuthenticatedMessage msg = p2.getMessage(7777);
		
		System.out.println("REC " + Utilities.byteArrayToHexString(msg.message));
		assertTrue("Received data is not equal to sent data", Utilities.arrayEqual(TEST_DATA, msg.message));
		
		boolean error = false;
		try {
			AMT.register(TEST_ID2);
		} catch (PKIError e) {
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
