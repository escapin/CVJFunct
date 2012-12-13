package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

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
interface PKIServer extends java.rmi.Remote {
	boolean pki_register(byte[] id, byte[] pubKey) throws RemoteException;
	byte[] pke_getPublicKey(byte[] id) throws RemoteException;
}

/**
 * Real functionality for PKI (Public Key Infrastructure).
 */
public class PKI extends UnicastRemoteObject implements PKIServer {

/// The public interface ///
	
	/** An object encapsulating the public key of some party. 
	 *  This key can be accessed directly of indirectly via method encrypt.  
	 */
	static public class Encryptor implements Serializable {
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
	static public class Decryptor implements Serializable {
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
		KeyPair keypair = CryptoLib.generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);  
		if(!getInstance().pki_register(id, publicKey)) return null; // registration has not succeeded (id already used)
		return new Decryptor(publicKey, privateKey);
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		// fetch the public key of id
		byte[] publKey = getInstance().pke_getPublicKey(id);
		if( publKey==null ) return null;
		return new Encryptor(publKey);
	}
	
/// Extended interface (not in the ideal functionality): serialization/deserialization of decryptors ///
	
	public static byte[] decryptorToBytes(Decryptor decryptor) {
		ByteArrayOutputStream bo = new ByteArrayOutputStream();
		try {
			ObjectOutputStream os = new ObjectOutputStream(bo);
			os.writeObject(decryptor);
			os.flush();
			os.close();
			return bo.toByteArray(); 
		} catch (IOException e) {
			System.err.println("An error occured while serializing the Decryptor: " + e.getMessage());
		}
		return null;
	}
	
	public Decryptor decryptorFromBytes(byte[] bytes) {
		try {			
			ByteArrayInputStream bi = new ByteArrayInputStream(bytes);
			ObjectInputStream os = new ObjectInputStream(bi);
			Decryptor decryptor = (Decryptor) os.readObject();
			return decryptor;
		} catch (Exception e) {
			System.err.println("An error occured while serializing the Decryptor: " + e.getMessage());			
		}
		return null; 
	}
	
/// Implementation ///
	private static final long serialVersionUID = 7924325010095445454L;
	private static PKI instance = null;
	private static boolean useRemote = false; // Local or RMI Mode? Depending on System properties
	private static PKI getInstance() {
		if (instance == null) {
			try {
				instance = new PKI();	
			} catch (Exception e) {
				System.out.println("There was an error with remoting: " + e.getMessage());
			}
		}
		return instance;
	}
	
	protected PKI() throws RemoteException {
		super();
	}
	
	static {
		// In case server property has been set, we register RMI server
		if (Boolean.parseBoolean(System.getProperty("server"))) {
			// Register RMI Server here, Default port 8661
			try {
				LocateRegistry.createRegistry(2020);
				Naming.rebind("//localhost:2020/server", getInstance());				
				System.out.println("Server registered successfully.");
			} catch (Exception e) {
				System.out.println("Error while registering RMI registry: " + e.getMessage());
			}
		}
		useRemote = Boolean.parseBoolean(System.getProperty("client"));
	}
	
	private HashMap<byte[], byte[]> pkLst = new HashMap<>(); 
	
	public boolean pki_register(byte[] id, byte[] pubKey) {
		if (useRemote) {
			try {
				PKIServer server = (PKIServer) Naming.lookup("//localhost:2020/server");
				boolean registered = server.pki_register(id, pubKey);
				return registered;
			} catch (MalformedURLException | RemoteException | NotBoundException e) {
				System.out.println("Could not resolve remote interface: " + e.getMessage());
			}
			return false;
		} else {			
			// If pk is already registered, return false
			if (pkLst.containsKey(id)) {
				return false;
			}
	
			// Add key to the list and return
			pkLst.put(id, pubKey);
			return true;
		}
	}
	
	public byte[] pke_getPublicKey(byte[] id) {
		if (useRemote) {
			try {
				PKIServer server = (PKIServer) Naming.lookup("server");
				return server.pke_getPublicKey(id);
			} catch (MalformedURLException | RemoteException | NotBoundException e) {
				System.out.println("Could not resolve remote interface: " + e.getMessage());
			}
			return null;
		} else {
			// Check if key in list
			return pkLst.get(id);
		}
	}
	
}

