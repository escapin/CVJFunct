package de.uni.trier.infsec.functionalities.pkenc.real;

import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.lib.crypto.CryptoLib;

//THIS FUNCTIONALITY IS OBSOLETE. USE PKI INSTEAD.

/**
 * Real functionality for public-key encryption: Decryptor
 */
public final class Decryptor {
	
	private byte[] publKey = null;
	private byte[] privKey = null; 

	public Decryptor() {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		publKey = keypair.publicKey;  
		privKey = keypair.privateKey; 
	}

    public Encryptor getEncryptor() {
        return new Encryptor(publKey);
    }

	public byte[] decrypt(byte[] message) {
		return CryptoLib.pke_decrypt(message, privKey);
	}
	
	// methods not present in the ideal functionality:
	
	public Decryptor(byte[] publKey, byte[] privKey) {
		this.publKey = publKey;
		this.privKey = privKey;
	}
	
	public byte[] pulicKey() {
		return publKey;
	}
	
	public byte[] privateKey() {
		return privKey;
	}
		
}
