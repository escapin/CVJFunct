package de.unitrier.infsec.functionalities.symenc;

import static de.unitrier.infsec.utils.MessageTools.copyOf;
import de.unitrier.infsec.lib.crypto.CryptoLib;

/**
 * Real functionality for private symmetric key encrytpion.
 * 
 * This functionality is meant to be used, if a user wants to generate
 * a symmetric key to be used solely by her. The functionality provides
 * no means to share the key. The key is generated in the constructor
 * and never leaves the object.
 */
public class SymEnc {
	private byte[] key;
	
	public SymEnc() {
		key = CryptoLib.symkey_generateKey();
	}
	
	public byte[] encrypt(byte[] plaintext) {
		return CryptoLib.symkey_encrypt(copyOf(key), copyOf(plaintext));
	}
	
	public byte[] decrypt(byte[] ciphertext) {
		return CryptoLib.symkey_decrypt(copyOf(key), copyOf(ciphertext));
	}
	
	/// Extended interface (not in the ideal functionality): serialization/deserialization of SymEnc ///
	
	public SymEnc(byte[] key){
		this.key=key;
	}
	
	public byte[] getKey(){
		return key;
	}
}
