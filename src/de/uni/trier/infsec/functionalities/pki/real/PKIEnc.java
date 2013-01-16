package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Arrays;

import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
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
	 */
	public static Decryptor register(byte[] id) {
		if (pki_server == null) return null;

		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);
		try {
			SignedMessage responce = pki_server.register(copyOf(id), copyOf(publicKey));
			if( responce == null) {
				// registration failed, perhaps because id has been already claimed.
				// TODO: (later) it would be useful to distinguish this reason (id has been claimed)
				// from some other possible problems.
				System.out.println("Did not receive any response from server");
				return null;
			}
			if (remoteMode) {
				byte[] id_from_data = MessageTools.first(responce.message);
				// Verify Signature!
				if (!CryptoLib.verify(responce.message, responce.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
					System.out.println("Signature verification failed!");
					return null;
				}
				// Verify that the response message contains the correct id
				if (!Utilities.arrayEqual(id, id_from_data)) {
					System.out.println("ID in response message is not equal to expected id!");
					return null;
				}
			}
		}
		catch (RemoteException e) {
			e.printStackTrace();
			return null;
		}

		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		try {
			SignedMessage responce = pki_server.getPublicKey(id);
			if( responce==null ) return null;
			byte[] data = responce.message;
			byte[] publKey = MessageTools.second(data);
			if (remoteMode) {
				byte[] id_from_data = MessageTools.first(data);
				// Verify Signature
				if(!CryptoLib.verify(data, responce.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
					System.out.println("Signature verification failed!");
					return null;
				}
				
				// Verify that the response message contains the correct id (Always use arrayEqual, not '==' which only compares references)
				if (!Utilities.arrayEqual(id, id_from_data)) {
					System.out.println("ID in response message is not equal to expected id!");
					return null;
				}
			}
			return new Encryptor(publKey);
		}
		catch (RemoteException e) {
			return null;
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
	// FIXME: does it make sense (can we simply create an instance of PKIServer?)
	// Well, there are two modes here:
	// 1. We use local mode, which means we instantiate the Server locally and run the methods on the local instance
	// 2. We use remote mode, which means we do not instantiate a server, but we use the Proxy interface and use the remote object for the method calls
	//    In RPC this happens invisibly, so the function calls remain the same, only instead of an instanciation, we use a call to "Naming.lookup".
	// So in the end, I think this should be fine?!
	static {
		try {
			if(remoteMode) {
				pki_server = (PKIServerInterface) Naming.lookup("//" + PKIServer.HOSTNAME + ":" + PKIServer.PORT + "/server");
				System.out.println("Working in remote mode. Using RPC Server " + PKIServer.HOSTNAME + ":" + PKIServer.PORT + "/server");
			}
			else {
				pki_server = new PKIServer();
				System.out.println("Working in local mode.");
			}
		} catch (MalformedURLException | RemoteException | NotBoundException e) {
			System.out.println("Cannot create a remote object PKIServer");
			pki_server = null; // probably redundant
		}
	}
}
