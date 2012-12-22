package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.HashMap;

import de.uni.trier.infsec.environment.crypto.KeyPair; 
import de.uni.trier.infsec.lib.crypto.CryptoLib; // TODO change to environment
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

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
			return new Encryptor(copyOf(publicKey));
		}
	}
		
	/** Registers a user with the given id. 
	 * 
	 *   It fails (returns null) if this id has been already registered. Otherwise, it creates
	 *   new decryptor (with fresh public/private keys) and registers it under the given id. 
	 */
	public static Decryptor register(byte[] id) {
		if (localMode) {
			KeyPair keypair = CryptoLib.pke_generateKeyPair();
			byte[] privateKey = copyOf(keypair.privateKey);
			byte[] publicKey = copyOf(keypair.publicKey);  
			if( !pki_register(copyOf(id), copyOf(publicKey)) ) return null; // registration has not succeeded (id already used)
			return new Decryptor(publicKey, privateKey);
		} else {
			PKIServerInterface server;
			try {
				server = (PKIServer) Naming.lookup("//" + PKIServer.HOSTNAME + ":" + PKIServer.PORT + "/server");
				byte[] bytes = server.register(id);
				byte[] data = MessageTools.first(bytes);
				byte[] signature = MessageTools.second(bytes);
				
				if (CryptoLib.ds_verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {					
					return decryptorFromBytes(data);
				} else {
					return null;
				}
			} catch (MalformedURLException | RemoteException | NotBoundException e) {
				System.out.println("There was an error with Remoting: " + e.getMessage());
			}
			return null;
		}
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		if (localMode) {			
			// fetch the public key of id
			byte[] publKey = pke_getPublicKey(id);
			if( publKey==null ) return null;
			return new Encryptor(publKey);
		} else {
			try {
				PKIServer server = (PKIServer) Naming.lookup("server");
				byte[] bytes = server.getPublicKey(id);
				byte[] data = MessageTools.first(bytes);
				byte[] signature = MessageTools.second(bytes);
				if (CryptoLib.ds_verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {					
					Encryptor encryptor = new Encryptor(data);
					return encryptor;
				} else {
					return null;
				}
				
			} catch (MalformedURLException | RemoteException | NotBoundException e) {
				System.out.println("There was an error with Remoting: " + e.getMessage());
			}
		}
		return null;
	}
		

/// Extended interface (not in the ideal functionality): serialization/deserialization of decryptors ///
	
	public static byte[] decryptorToBytes(Decryptor decryptor) {
		byte[] priv = decryptor.privateKey;
		byte[] publ = decryptor.publicKey;
		
		byte[] out = MessageTools.concatenate(priv, publ);
		return out; 
	}
	
	public static Decryptor decryptorFromBytes(byte[] bytes) {
		byte[] priv = MessageTools.first(bytes);
		byte[] publ = MessageTools.second(bytes);
		
		Decryptor decryptor = new Decryptor(publ, priv);
		return decryptor; 
	}

/// Implementation ///
	
	private static HashMap<String, byte[]> pkLst = new HashMap<>();
	
	private static boolean localMode = true;
	static {
		if (!Boolean.parseBoolean(System.getProperty("localmode"))) localMode = false;
	}

	private static boolean pki_register(byte[] id, byte[] pubKey) {
		// Key of the HashMap is not the id itself but its String (Hex) representation, because we´d need "array-Equal" for byte arrays.
		if (pkLst.containsKey(Utilities.byteArrayToHexString(id))) {
			return false;
		}
		pkLst.put(Utilities.byteArrayToHexString(id), pubKey);
		return true;
	}
	
	private static byte[] pke_getPublicKey(byte[] id) {
		return pkLst.get(Utilities.byteArrayToHexString(id));
	}
}

