package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;

import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.lib.crypto.Encryption;


/**
 * Interface for Java RMI Implementation
 */
interface PKIServer extends java.rmi.Remote {
	boolean pki_register(byte[] id, byte[] pubKey) throws RemoteException;
	byte[] pke_getPublicKey(byte[] id) throws RemoteException;
}


/**
 * Real functionality for PKI (Public Key Infrastructure).
 */
public class PKI extends UnicastRemoteObject implements PKIServer {

	// The public interface //
	public static class Decryptor {
		private byte[] privateKey;
		
		private Decryptor(byte[] privateKey) {
			this.privateKey = privateKey;
		}
		
		public byte[] decrypt(byte[] message) {
			// decrypt 'ciphertext' using our private key
			return copyOf(Encryption.decrypt(copyOf(message), copyOf(privateKey)));
		}	
	}
	
	// Singleton implementation
	public static Decryptor register(byte[] id) {
		KeyPair keypair = Encryption.generateKeyPair();
		byte[] privateKey = copyOf(keypair.privateKey);
		byte[] publicKey = copyOf(keypair.publicKey);  
		if(!getInstance().pki_register(id, publicKey)) return null; // registration has not succeeded
		return new Decryptor(privateKey);
	}
	
	public static byte[] encryptFor(byte[] id, byte[] message) {
		// fetch the public key of id
		byte[] publKey = getInstance().pke_getPublicKey(id);
		if( publKey == null ) return null;
		// encrypt 'message' using this public key
		return copyOf(Encryption.encrypt(copyOf(message), copyOf(publKey)));
	}
	
	public static byte[] getPublicKey(byte[] id) {
		return copyOf(getInstance().pke_getPublicKey(id));
	}
	

	// The extended public interface (not implemented in the ideal functionality) //
	public void save(String filename) {
		// ....
	}
	
	public static Decryptor load(String filename) {
		byte[] privateKey = null; 
		// .....
		return new Decryptor(privateKey);
	}

	private static final long serialVersionUID = 7924325010095445454L;
	private static PKI instance = null;
	private static boolean useRemote = false; // Local or RMI Mode? Depending on System properties
	public static PKI getInstance() {
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
	
	// Implementation //
	
	// Backend implementation //
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

