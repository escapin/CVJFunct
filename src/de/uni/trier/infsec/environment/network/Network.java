package de.uni.trier.infsec.environment.network;

import de.uni.trier.infsec.environment.Environment;

public class Network {

	public static void networkOut(byte[] outEnc) throws NetworkError {
		// input
		Environment.untrustedOutput(0x55);
		Environment.untrustedOutputMessage(outEnc);		
		// output
		if (Environment.untrustedInput()==0) throw new NetworkError();
	}

	public static byte[] networkIn() throws NetworkError {
		// input
		Environment.untrustedOutput(0x56);		
		// output
		if (Environment.untrustedInput()==0) throw new NetworkError();
		return Environment.untrustedInputMessage();
	}
}
