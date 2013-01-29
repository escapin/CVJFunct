package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

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
	public static Decryptor register(int id) throws NetworkError, PKIError {
		if (pki_server == null) throw new PKIError();

		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);
		SignedMessage responce = pki_server.register(id, copyOf(publicKey));
		if( responce == null) {
			// registration failed, perhaps because id has been already claimed.
			System.out.println("Did not receive any response from server");
			return null;
		}
		if (remoteMode) {
			// Verify Signature first!
			if (!CryptoLib.verify(responce.message, responce.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
				System.out.println("Signature verification failed!");
				return null;
			}
			
			if (Utilities.arrayEqual(responce.message, PKIServerInterface.MSG_ERROR_REGISTRATION)) {
				System.out.println("Server responded with registration error");
				throw new PKIError();
			}
			
			// Verify that the response message contains the correct id and public key
			int id_from_data = MessageTools.byteArrayToInt(MessageTools.first(responce.message));
			byte[] pk_from_data = MessageTools.second(responce.message);
			if (id != id_from_data) {
				System.out.println("ID in response message is not equal to expected id: \nReceived: " +  id + "\nExpected: " + id_from_data);
				return null;
			}
			if (!Utilities.arrayEqual(pk_from_data, publicKey)) {
				System.out.println("PK in response message is not equal to expected id: \nReceived: " + Utilities.byteArrayToHexString(pk_from_data) + "\nExpected: " + Utilities.byteArrayToHexString(publicKey));
				return null;
			}
		}
		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(int id) throws NetworkError, PKIError {
		try {
			SignedMessage responce = pki_server.getPublicKey(id);
			if( responce==null ) return null;
			byte[] data = responce.message;
			byte[] publKey;
			if (remoteMode) {
				publKey = MessageTools.second(data);
				int id_from_data = MessageTools.byteArrayToInt(MessageTools.first(data));
				// Verify Signature
				if(!CryptoLib.verify(data, responce.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
					System.out.println("Signature verification failed!");
					return null;
				}
				
				// Verify that the response message contains the correct id
				if (id != id_from_data) {
					System.out.println("ID in response message is not equal to expected id: \nReceived: " + 
							id + "\nExpected: " + id_from_data);
					return null;
				}
			} else {
				int id_from_data = MessageTools.byteArrayToInt(MessageTools.first(data));
				if (id != id_from_data) {
					System.out.println("ID in response message is not equal to expected id: \nReceived: " + 
							id + "\nExpected: " + id_from_data);
					return null;
				}
				publKey = MessageTools.second(data);
			}
			return new Encryptor(publKey);
		} catch (NetworkError e) {
			throw new Error(); // possibly network error
		}
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
