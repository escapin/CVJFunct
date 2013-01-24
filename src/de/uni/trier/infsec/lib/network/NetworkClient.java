package de.uni.trier.infsec.lib.network;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class NetworkClient {
	
	/**
	 * Sends message to the given server/port (without waiting for any response)
	 */
	public static void send(byte[] message, String server, int port) throws NetworkError {
		Socket s = null;
		try {
			s = new Socket(server, port);
			OutputStream os = s.getOutputStream();			
			os.write(message);
			os.flush();
		} catch (Exception e) {
			e.printStackTrace();
			throw new NetworkError();
		} finally {
			try { s.close(); } catch (Exception e) {}
		}
	}

	/**
	 * Sends message to the given server/port and gets the response
	 * (also a message).
	 */
	public static byte[] sendRequest(byte[] message, String server, int port) throws NetworkError {
		Socket s = null;
		try {
			s = new Socket(server, port);
			OutputStream os = s.getOutputStream();
			
			os.write(message);
			os.flush();
			
			InputStream is = s.getInputStream();
			ByteArrayOutputStream buffer = new ByteArrayOutputStream(); // we can handle Messages up to 1K
			byte[] bufferArr = new byte[512];
			
			buffer.write(bufferArr, 0, is.read(bufferArr)); // This first call is necessary for the call to become blocking!
				// XXX: I do not quite get it (which is ok:)), but why you do not use this in the server's code?
			// TODO: Timeout needed? -- yes, I thing it should give up after some reasonable time.
			while (is.available() > 0) buffer.write(bufferArr, 0, is.read(bufferArr));
			return buffer.toByteArray();
			
		} catch (Exception e) {
			e.printStackTrace();
			throw new NetworkError();
		} finally {
			try { s.close(); } catch (Exception e) {}
		}
	}
	
	
	
//	public static void main(String[] args) throws NetworkError {
//		byte[] out = send(new byte[] {(byte) 0x99,  (byte) 0x88}, "127.0.0.1", 7070);
//		System.out.println(Utilities.byteArrayToHexString(out));
//	}

}
