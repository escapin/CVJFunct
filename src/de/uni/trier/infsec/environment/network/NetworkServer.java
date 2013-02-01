package de.uni.trier.infsec.environment.network;

import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.lib.network.NetworkError;

public class NetworkServer {

	public static byte[] nextRequest() throws NetworkError {
		// input
		Environment.untrustedOutput(0x2401);
		// output
		if ( Environment.untrustedInput()==0 ) throw new NetworkError();
		return Environment.untrustedInputMessage();
	}

	public static void response(byte[] message) throws NetworkError {
		// input
		Environment.untrustedOutput(0x2402);
		Environment.untrustedOutputMessage(message);
		// output
		if ( Environment.untrustedInput()==0 ) throw new NetworkError();		
	}

	public static byte[] read() throws NetworkError {
		// input
		Environment.untrustedOutput(0x2403);
		// output
		if ( Environment.untrustedInput()==0 ) throw new NetworkError();
		return Environment.untrustedInputMessage();		
	}
}
