package de.uni.trier.infsec.functionalities.pki.ideal;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.functionalities.pki.ideal.PKIError;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for public-key encryption with PKI (Public Key Infrastructure).
 * 
 * The intended usage is as follows. An agent who wants to use this functionality to
 * receive (decrypt) messages must first register herself to obtain its, so called, 
 * decryptor: 
 * 
 *     PKIEnc.Decryptor decryptor_of_A = PKIEnc.register(ID_OF_A);
 *        
 * Another agent can encrypt messages for A as follows:
 *  
 *     PKIEnc.Encryptor encryptor_for_A = getEncryptor(ID_OF_A);
 *     byte[] ciphertext1 = encryptor_for_A.encrypt(message1);
 *     byte[] ciphertext2 = encryptor_for_A.encrypt(message2);
 *     
 * A can decrypt such messages using her decryptor:
 * 
 *     byte[] message = decryptor_of_A.decrypt(ciphertext);
 */
public class PKIEnc {
	
/// The public interface ///

	/** An object encapsulating the public key of some party.
	 *  
	 *  This key can be accessed directly of indirectly via method encrypt.
	 *  Method 'encrypt' realizes the "ideal" encryption, where a string of 
	 *  zeros is encrypted instead of the original message and the pair 
	 *  (plaintext, ciphertest) is stored in a log which can be then used
	 *  for decryption.    
	 */
	static public class Encryptor {
		private int ID;	
		private byte[] publicKey;
		private EncryptionLog log;

		private Encryptor(int id, byte[] publicKey, EncryptionLog log) {
			this.ID = id;
			this.publicKey = publicKey;
			this.log = log;
		}
		
		public byte[] encrypt(byte[] message) {
			byte[] randomCipher = null;
			// keep asking the environment for the ciphertext, until a fresh one is given:
			while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
				randomCipher = copyOf(CryptoLib.pke_encrypt(getZeroMessage(message.length), copyOf(publicKey)));
			}
			log.add(copyOf(message), randomCipher);
			return copyOf(randomCipher);
		}

		public byte[] getPublicKey() {
			return copyOf(publicKey);
		}
	}
	
	/** An object encapsulating the private and public keys of some party. */
	static public class Decryptor {
		private int ID;
		private byte[] publicKey;
		private byte[] privateKey;
		private EncryptionLog log;

		private Decryptor(int id) {
			KeyPair keypair = CryptoLib.pke_generateKeyPair();
			this.privateKey = copyOf(keypair.privateKey);
			this.publicKey = copyOf(keypair.publicKey);
			this.ID = id;
			this.log = new EncryptionLog();
		}		
		
		/** "Decrypts" a message by, first trying to find in in the log (and returning
		 *   the related plaintext) and, only if this fails, by using real decryption. */
		public byte[] decrypt(byte[] message) {
			byte[] messageCopy = copyOf(message); 
			if (!log.containsCiphertext(messageCopy)) {
				return copyOf( CryptoLib.pke_decrypt(copyOf(privateKey), messageCopy) );
			} else {
				return copyOf( log.lookup(messageCopy) );
			}			
		}
		
		/** Returns a new encryptor object sharing the same public key, ID, and log. */
		public Encryptor getEncryptor() {
			return new Encryptor(ID, publicKey, log);
		}	
	}

	/**
	 * We assume that the registration process is not blocked (no network problems).
	 */
	public static Decryptor register(int id) throws PKIError {
		Environment.untrustedOutput(id);
		if( registeredAgents.fetch(id) != null ) throw new PKIError(); // a party with this id has already registered
		Decryptor decryptor = new Decryptor(id);
		Encryptor encryptor = decryptor.getEncryptor();
		registeredAgents.add(encryptor);
		return decryptor;
	}
	
	public static Encryptor getEncryptor(int id) throws NetworkError, PKIError {
		if( Environment.untrustedInput() == 0 )  throw new NetworkError();
		Encryptor enc = registeredAgents.fetch(id);
		if (enc == null) throw new PKIError(); // there is no registered agent with this id
		return enc;
	}
	
	
/// Implementation ///

	private static class EncryptionLog {
		
		private static class MessagePairList {
			byte[] ciphertext;
			byte[] plaintext;
			MessagePairList next;
			public MessagePairList(byte[] ciphertext, byte[] plaintext, MessagePairList next) {
				this.ciphertext = ciphertext;
				this.plaintext = plaintext;
				this.next = next;
			}
		}

		private MessagePairList first = null;
		
		public void add(byte[] plaintext, byte[] ciphertext) {
			first = new MessagePairList(ciphertext, plaintext, first);
		}

	    byte[] lookup(byte[] ciphertext) {	    	
	    	for( MessagePairList node = first;  node != null;  node = node.next ) {
	            if( MessageTools.equal(node.ciphertext, ciphertext) )
	                return node.plaintext;	    		
	    	}
	        return null;
	    }
	    
	    boolean containsCiphertext(byte[] ciphertext) {
	    	return lookup(ciphertext) != null;
	    }    
	}


	private static class RegisteredAgents {
		private static class EncryptorList {
			Encryptor encryptor;
			EncryptorList  next;
			EncryptorList(Encryptor encryptor, EncryptorList next) {
				this.encryptor= encryptor;
				this.next = next;
			}
		}

		private EncryptorList first = null;
		
		public void add(Encryptor encr) {
			first = new EncryptorList(encr, first);
		}
		
		Encryptor fetch(int ID) {
			for( EncryptorList node = first;  node != null;  node = node.next ) {
				if( ID == node.encryptor.ID )
					return node.encryptor;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();	
}