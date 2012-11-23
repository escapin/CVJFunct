package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;




/**
 * Real functionality for PKI (Public Key Infrastructure).
 */
public class PKI {

/// The public interface ///
	
	static public class Encryptor {
		private byte[] publicKey;	
		private Encryptor(byte[] publicKey) {
			this.publicKey = publicKey;
		}
		public byte[] encrypt(byte[] message) {
			return copyOf(CryptoLib.pke_encrypt(copyOf(message), copyOf(publicKey)));		
		}
		public byte[] getPublicKey() {
			return publicKey;
		}
	}
	
	static public class Decryptor {
		private byte[] publicKey;
		private byte[] privateKey;
		private Decryptor(byte[] publicKey, byte[] privateKey) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}
		public byte[] decrypt(byte[] message) {
			return copyOf(CryptoLib.pke_decrypt(copyOf(message), copyOf(privateKey)));
		}	
		public Encryptor getEncryptor() {
			return new Encryptor(publicKey);
		}
	}
		
	public static Decryptor register(byte[] id) {
		KeyPair keypair = CryptoLib.generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);  
		if( !pki_register(id, publicKey) ) return null; // registration has not succeeded
		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		// fetch the public key of id
		byte[] publKey = pke_getPublicKey(id);
		if( publKey==null ) return null;
		return new Encryptor(publKey);
	}
		

/// Implementation ///
	
	private static boolean pki_register(byte[] id, byte[] pubKey)
		{return false;}
	private static byte[] pke_getPublicKey(byte[] id)
		{return null;}
}
