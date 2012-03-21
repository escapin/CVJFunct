package de.uni.trier.infsec.lib.network;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import de.uni.trier.infsec.environment.network.NetworkError;

// [tt] Should have the same interface as environment.network.Network, but provide a "real" networking.
// (perhaps interface needs to be extended)
// TODO [AK] This very simple implementation is stateless, so it can be used by a single call... 
// Do we prefer some kind of state? (Add connect-String as parameter or make it stateful and add a connect-Method?)
public class Network {
	
	public static final int PORT = 4242;
	public static final String SERVER = "127.0.0.1";
	
	// NetworkOut is actually stateless - so connect, send a message and disconnect.
	public static void networkOut(byte[] outEnc) throws NetworkError {
		Socket s = null;
		try {
			s = new Socket(SERVER, PORT);
			s.getOutputStream().write(outEnc.length);
			s.getOutputStream().write(outEnc);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (s != null) s.close();
			} catch (Exception e) {} // swallow exception
		}
	}

	
	// Actually networkIn calls blocking read on Socket. 
	// If we want to run it on one machine, we have to care for threading...
	public static byte[] networkIn() throws NetworkError {
		byte[] buffer = null;
		Socket s = null;
		try {
			ServerSocket server = new ServerSocket(PORT);
			s = server.accept();
			int length = s.getInputStream().read();
			buffer = new byte[length];
			s.getInputStream().read(buffer);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				if (s != null) s.close();
			} catch (Exception e) {} // swallow exception
		}
		return buffer;
	}
	
}
