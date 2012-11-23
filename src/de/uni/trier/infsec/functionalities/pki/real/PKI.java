package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;




/**
 * Real functionality for PKI (Public Key Infrastructure).
 */
public class PKI {

/// The public interface ///

	static public class Decryptor {
		private byte[] privateKey;
		
		private Decryptor(byte[] privateKey) {
			this.privateKey = privateKey;
		}
		
		public byte[] decrypt(byte[] message) {
			// decrypt 'ciphertext' using our private key
			return copyOf(CryptoLib.pke_decrypt(copyOf(message), copyOf(privateKey)));
		}	
	}
		
	public static Decryptor register(byte[] id) {
		KeyPair keypair = CryptoLib.generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);  
		if( !pki_register(id, publicKey) ) return null; // registration has not succeeded
		return new Decryptor(privateKey);
	}
	
	public static byte[] encryptFor(byte[] id, byte[] message) {
		// fetch the public key of id
		byte[] publKey = pke_getPublicKey(id);
		if( publKey==null ) return null;
		// encrypt 'message' using this public key
		return copyOf(CryptoLib.pke_encrypt(copyOf(message), copyOf(publKey)));
	}
	
	public static byte[] getPublicKey(byte[] id) {
		return copyOf(pke_getPublicKey(id));
	}
	

/// The extended public interface (not implemented in the ideal functionality) ///
	
	public void save(String filename) {
		// ....
	}
	
	public static Decryptor load(String filename) {
		byte[] privateKey = null; 
		// .....
		return new Decryptor(privateKey);
	}
	
/// Implementation ///

	
/// Backend implementation ///
	
	private static boolean pki_register(byte[] id, byte[] pubKey)
		{return false;}
	private static byte[] pke_getPublicKey(byte[] id)
		{return null;}
}
