package de.uni.trier.infsec.protocols.smt_voting;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

import de.uni.trier.infsec.utils.Utilities;

public class BulletinBoardRequestTool {

	public static void main(String[] args) {
		BulletinBoardRequestTool.runRequest();
	}

	private static void runRequest() {
		Socket s = null;
		try {
			s = new Socket(Identifiers.DEFAULT_HOST_BBOARD, Identifiers.DEFAULT_LISTEN_PORT_BBOARD_REQUEST);
			s.setSoTimeout(5000);
			InputStream is = s.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			byte[] bufferArr = new byte[512];
			do {
				int receivedBytesCount = is.read(bufferArr);
				buffer.write(bufferArr, 0, receivedBytesCount);
			} while (is.available() > 0);
			
			byte[] response = buffer.toByteArray();
			if ( response != null && response.length > 0) {				
				System.out.println("Received data from bulletin board:\n0x" + Utilities.byteArrayToHexString(response));
			} else {
				System.out.println("Did not receive any response from bulletin board.");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (s != null) s.close();
			} catch (IOException e) {}
		}
	}
}
