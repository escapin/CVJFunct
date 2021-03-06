package tests;

import org.junit.Test;

import junit.framework.TestCase;
import lib.network.NetworkClient;
import lib.network.NetworkError;
import lib.network.NetworkServer;
import utils.Utilities;

public class TestNetwork extends TestCase {

	public static byte[] TEST_DATA = {0x03, 0x42, 0x03, 0x03, 0x42, 0x03, 0x03, 0x42, 0x03, 0x03, 0x42, 0x03, 0x03, 0x42, 0x03, 0x03, 0x42, 0x03};
	public static byte[] TEST_DATA_2 = {0x0F, 0x42, 0x0F, 0x0F, 0x42, 0x0F, 0x0F, 0x42, 0x0F, 0x0F, 0x42, 0x0F, 0x0F, 0x42, 0x0F, 0x0F, 0x42, 0x0F};
	public static byte[] clientResponse = null;
	public static int LISTEN_PORT = 7070;
	
	@Test
	public void testNetworking() throws NetworkError, InterruptedException {
		NetworkServer.listenForRequests(LISTEN_PORT);
		Runnable r = new Runnable() {
			@Override
			public void run() {
				try {
					clientResponse = NetworkClient.sendRequest(TEST_DATA, "127.0.0.1", LISTEN_PORT);
				} catch (NetworkError e) {
					fail(e.getMessage());
				}
			}
		};
		
		Thread t = new Thread(r);
		t.start();
		Thread.sleep(2000); // Wait for the message to be sent and received
		byte[] received = NetworkServer.nextRequest(LISTEN_PORT);
		NetworkServer.response(TEST_DATA_2);
		Thread.sleep(2000); // Wait for the message to be sent and received
		System.out.println("Server received: 0x" + Utilities.byteArrayToHexString(received));
		System.out.println("Client received: 0x" + Utilities.byteArrayToHexString(clientResponse));
		
		assertTrue("The data has changed while transport!", Utilities.arrayEqual(received, TEST_DATA));
		assertTrue("The client data has changed while transport!", Utilities.arrayEqual(clientResponse, TEST_DATA_2));	
	}
}