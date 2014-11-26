package de.unitrier.infsec.functionalities.pkenc;

import de.unitrier.infsec.lib.crypto.CryptoLib;

//THIS FUNCTIONALITY IS OBSOLETE. USE PKI INSTEAD.

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
		return CryptoLib.pke_encrypt(message, publKey);
	}
	
}
