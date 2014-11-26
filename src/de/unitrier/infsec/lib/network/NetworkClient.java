package de.unitrier.infsec.lib.network;

import de.unitrier.infsec.environment.Environment;

public class NetworkClient {

	public static void send(byte[] message, String server, int port) throws NetworkError {
		// input
		Environment.untrustedOutput(0x2301);
		Environment.untrustedOutputMessage(message);
		Environment.untrustedOutputString(server);
		Environment.untrustedOutput(port);
		// output
		if ( Environment.untrustedInput()==0 ) throw new NetworkError();
	}

	public static byte[] sendRequest(byte[] message, String server, int port) throws NetworkError {
		// input
		Environment.untrustedOutput(0x2302);
		Environment.untrustedOutputMessage(message);
		Environment.untrustedOutputString(server);
		Environment.untrustedOutput(port);
		// output
		if ( Environment.untrustedInput()==0 ) throw new NetworkError();
		return Environment.untrustedInputMessage();
	}
}
