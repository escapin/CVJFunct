package de.uni.trier.infsec.functionalities.pkenc.real;

import de.uni.trier.infsec.lib.crypto.Encryption;

/**
 * Real functionality for public-key encryption: Encryptor
 */
public final class Encryptor {

	private byte[] publKey = null;
	
	// Note that this constructor is not public in the ideal functionality. 
	public Encryptor(byte[] publicKey) { 
		publKey = publicKey;
	}
		
	public byte[] getPublicKey() {
		return publKey;
	}
	
	public byte[] encrypt(byte[] message) {
		return Encryption.encrypt(message, publKey);
	}
	
}
