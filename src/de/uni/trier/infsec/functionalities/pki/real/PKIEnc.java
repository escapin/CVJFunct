package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.lib.network.NetworkError;

/**
 * Real functionality for PKI (Public Key Infrastructure).
 * 
 * For intended usage, see functionalities.pki.ideal
 * 	
 * The serialization methods (decryptorToBytes, decryptorFromBytes)
 * can be used to store/restore a decryptor.
 *
 * In order to use remote PKI, simply start an instance of PKIServer 
 * and set Java Property -Dremotemode=true which will enable remote procedure 
 * calls to be used automatically. Server Authentication is done by signing and 
 * validating each message using an built-in keypair (see PKIServer).
 */
public class PKIEnc {
	
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
			return new Encryptor(copyOf(publicKey));
		}
	}
		
	/** Registers a user with the given id. 
	 * 
	 *   It fails (returns null) if this id has been already registered. Otherwise, it creates
	 *   new decryptor (with fresh public/private keys) and registers it under the given id.
	 *   Message format for registration:
	 *    
	 */
	public static Decryptor register(int id) throws PKIError, NetworkError {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);
		
		pki_server.registerPublicKey(id, copyOf(publicKey));
		
		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(int id) throws PKIError, NetworkError {
		byte[] publKey = pki_server.getPublicKey(id);
		
		return new Encryptor(publKey);
	}
		

/// Extended interface (not in the ideal functionality): serialization/deserialization of decryptors ///
	
	public static byte[] decryptorToBytes(Decryptor decryptor) {
		byte[] priv = decryptor.privateKey;
		byte[] publ = decryptor.publicKey;
		
		byte[] out = concatenate(priv, publ);
		return out; 
	}
	
	public static Decryptor decryptorFromBytes(byte[] bytes) {
		byte[] priv = first(bytes);
		byte[] publ = second(bytes);
		
		Decryptor decryptor = new Decryptor(publ, priv);
		return decryptor; 
	}
	
	private static boolean remoteMode = Boolean.parseBoolean(System.getProperty("remotemode"));
	private static PKIServerInterface pki_server = null;
	static {
		if(remoteMode) {
			pki_server = new RemotePKIServer();
			System.out.println("Working in remote mode");
		}
		else {
			pki_server = new PKIServerCore();
			System.out.println("Working in local mode");
		}
	}
}
