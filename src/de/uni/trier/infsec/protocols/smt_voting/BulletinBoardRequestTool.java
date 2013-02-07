package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class BulletinBoardRequestTool {

	public static void main(String[] args) {
		BulletinBoardRequestTool.runRequest();
	}

	private static void runRequest() {
		try {
			byte[] response = NetworkClient.sendRequest(new byte[] {0x01}, Parameters.DEFAULT_HOST_BBOARD, Parameters.DEFAULT_LISTEN_PORT_BBOARD_REQUEST);
			if ( response != null && response.length > 0) {				
				System.out.println("Received data from bulletin board:\n0x" + Utilities.byteArrayToHexString(response));
			} else {
				System.out.println("Did not receive any response from bulletin board.");
			}
		} catch (NetworkError e) {
			e.printStackTrace();
		}
	}
}
