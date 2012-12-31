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
	
	public static KeyPair pke_generateKeyPair() {
		// input
		Environment.untrustedOutput(0x88); // Function code for pke_generateKeyPair
		
		// ouptut
		KeyPair resval = null;
		if( Environment.untrustedInput()==0 ) {
			resval = new KeyPair();
			resval.privateKey = Environment.untrustedInputMessage();
			resval.publicKey = Environment.untrustedInputMessage();
		}
		return resval;
	}
	
	
	public static byte[] ds_sign(byte[] message, byte[] privKey) {
		// input
		Environment.untrustedOutput(0x11); // Function code for digital signature generation ds_sign
		Environment.untrustedOutputMessage(message);
		Environment.untrustedOutputMessage(privKey);		
		// output
		return Environment.untrustedInputMessage();
	}
	
	public static boolean ds_verify(byte[] message, byte[] signature, byte[] pubKey) {
		// input
		Environment.untrustedOutput(0x22); // Function code for digital signature verification ds_verify
		Environment.untrustedOutputMessage(message);
		Environment.untrustedOutputMessage(signature);
		Environment.untrustedOutputMessage(pubKey);		
		// output
		return Environment.untrustedInput() != 0; // TODO: Do we prefer byte[] as output?
	}

	public static KeyPair ds_generateKeyPair() {
		// input
		Environment.untrustedOutput(0x89); // Function code for ds_generateKeyPair
		
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
