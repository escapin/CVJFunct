package de.uni.trier.infsec.environment.crypto;

import de.uni.trier.infsec.environment.Environment;

public class CryptoLib {

	public static byte[] pke_encrypt(byte[] in, byte[] publKey) {
		// input
		Environment.untrustedOutput(0x66); // Function code for pke_encrypt
		Environment.untrustedOutputMessage(in);
		Environment.untrustedOutputMessage(publKey);
		// output
		return Environment.untrustedInputMessage();
	}

	public static byte[] pke_decrypt(byte[] message, byte[] privKey) {
		// input
		Environment.untrustedOutput(0x77); // Function code for pke_decrypt
		Environment.untrustedOutputMessage(message);
		Environment.untrustedOutputMessage(privKey);		
		// output
		return Environment.untrustedInputMessage();
	}

	public static KeyPair generateKeyPair() {
		// input
		Environment.untrustedOutput(0x88); // Function code for generateKeyPair
		
		// ouptut
		KeyPair resval = null;
		if( Environment.untrustedInput()==0 ) {
			resval = new KeyPair();
			resval.privateKey = Environment.untrustedInputMessage();
			resval.publicKey = Environment.untrustedInputMessage();
		}
		return resval;
	}
	
}
