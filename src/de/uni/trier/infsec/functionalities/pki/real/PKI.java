package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;

/**
 * Real functionality for PKI (Public Key Infrastructure).
 * 
 * The intended usage:
 * 
 * To encrypt messages for a party with identifier id_of_A: 
 * 		Encryptor encryptor_of_A = PKI.getEncryptor(id_A);
 * 		byte[] encrypted1 = encryptor_of_A.encrypt(message1);
 * 		byte[] encrypted2 = encryptor_of_A.encrypt(message2);
 * 
 * To register with my_id:
 * 		Decryptor my_decryptor = PKI.register(my_id);
 * 		if( my_decryptor == null ) 
 * 			//  somebody has already registered using my_id...
 * 		else
 * 			byte[] message = my_decryptor.decrypt(ciphertext)
 * 	
 *	The serialization methods (decryptorToBytes, decryptorFromBytes)
 *	can be used to store/restore a decryptor.
 */
public class PKI {

/// The public interface ///
	
	/** An object encapsulating the public key of some party. 
	 *  This key can be accessed directly of indirectly via method encrypt.  
	 */
	static public class Encryptor {
		private byte[] publicKey;	
		
		private Encryptor(byte[] publicKey) {
			this.publicKey = publicKey;
		}
		
		public byte[] encrypt(byte[] message) {
			return copyOf(CryptoLib.pke_encrypt(copyOf(message), copyOf(publicKey)));		
		}
		
		public byte[] getPublicKey() {
			return copyOf(publicKey);
		}
	}
	
	/** An object encapsulating the private and public keys of some party. */
	static public class Decryptor {
		private byte[] publicKey;
		private byte[] privateKey;
		
		private Decryptor(byte[] publicKey, byte[] privateKey) {
			this.publicKey = publicKey;
			this.privateKey = privateKey;
		}
		
		/** Decrypts 'message' with the encapsulated private key. */
		public byte[] decrypt(byte[] message) {
			return copyOf(CryptoLib.pke_decrypt(copyOf(message), copyOf(privateKey)));
		}	
		
		/** Returns a new encryptor object with the same public key. */
		public Encryptor getEncryptor() {
			return new Encryptor(publicKey);
		}
	}
		
	/** Registers a user with the given id. 
	 * 
	 *   It fails (returns null) if this id has been already registered. Otherwise, it creates
	 *   new decryptor (with fresh public/private keys) and registers it under the given id. 
	 */
	public static Decryptor register(byte[] id) {
		KeyPair keypair = CryptoLib.generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);  
		if( !pki_register(copyOf(id), copyOf(publicKey)) ) return null; // registration has not succeeded (id already used)
		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		// fetch the public key of id
		byte[] publKey = pke_getPublicKey(id);
		if( publKey==null ) return null;
		return new Encryptor(publKey);
	}
		

/// Extended interface (not in the ideal functionality): serialization/deserialization of decryptors ///
	
	public static byte[] decryptorToBytes(Decryptor decryptor)
		{ return null; }  // TODO
	
	public Decryptor decryptorFromBytes(byte[] bytes)
		{ return null; }  // TODO
	
/// Implementation ///
	
	private static boolean pki_register(byte[] id, byte[] pubKey)
		{return false;}  // TODO
	
	private static byte[] pke_getPublicKey(byte[] id)
		{return null;}	 // TODO
}
