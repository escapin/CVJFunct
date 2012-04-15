package de.uni.trier.infsec.lib.network;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import de.uni.trier.infsec.environment.network.NetworkError;

// [tt] Should have the same interface as environment.network.Network, but provide a "real" networking.
// (perhaps interface needs to be extended)
public class Network {
	
	public static final int DEFAULT_PORT = 4242;
	public static final String DEFAULT_SERVER = "127.0.0.1";
	
	private static Socket socket = null;
	private static ServerSocket ss = null;
	
	public static boolean connectToServer(String server, int port) {
		try {
			socket = new Socket(server, port);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}	
	}
		
	public static boolean waitForClient(int port) {
		if (ss == null) {
			try {
				ss = new ServerSocket(port);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		try {
			socket = ss.accept();
			return true;
		} catch (IOException e) {
			return false;
		}
	}
	
	public static void disconnect() {
		try {
			if (socket != null) socket.close();
			socket = null;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	// NetworkOut is actually stateless - so connect, send a message and disconnect.
	public static void networkOut(byte[] outEnc) throws NetworkError {
		try {
			if (socket == null) 
				return;
			socket.getOutputStream().write(outEnc.length);
			socket.getOutputStream().write(outEnc);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
	// Actually networkIn calls blocking read on Socket. 
	// If we want to run it on one machine, we have to care for threading...
	public static byte[] networkIn() throws NetworkError {
		if (socket == null) 
			return null;
		
		byte[] buffer = null;
		try {
			int length = socket.getInputStream().read();
			buffer = new byte[length];
			socket.getInputStream().read(buffer);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return buffer;
	}
	
}
