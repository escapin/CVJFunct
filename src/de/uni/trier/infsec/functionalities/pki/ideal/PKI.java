package de.uni.trier.infsec.functionalities.pki.ideal;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.equal;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for PKI (Public Key Infrastructure).
 */
public class PKI {
	
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
		private byte[] ID;	
		private byte[] publicKey;
		private EncryptionLog log;

		private Encryptor(byte[] id, byte[] publicKey, EncryptionLog log) {
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
		private byte[] ID;
		private byte[] publicKey;
		private byte[] privateKey;
		private EncryptionLog log;

		private Decryptor(byte[] id) {
			KeyPair keypair = CryptoLib.generateKeyPair();
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

	public static Decryptor register(byte[] id) {
		id = copyOf(id);
		if( handlers.fetch(id) != null ) return null; // a party with this id has already registered
		Decryptor decryptor = new Decryptor(id);
		Encryptor encryptor = decryptor.getEncryptor();
		handlers.add(encryptor);
		return decryptor;
	}
	
	public static Encryptor getEncryptor(byte[] id) {
		return handlers.fetch(id);
	}
	
	
/// Implementation ///
		
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
	
	private static class EncryptionLog {
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

		
	private static class EncrList {
		Encryptor encryptor;
		EncrList  next;
		EncrList(Encryptor encryptor, EncrList next) {
			this.encryptor= encryptor;
			this.next = next;
		}
	}
	
	private static class Handlers {	
		private EncrList first = null;
		
		public void add(Encryptor encr) {
			first = new EncrList(encr, first);
		}
		
		Encryptor fetch(byte[] ID) {
			for( EncrList node = first;  node != null;  node = node.next ) {
				if( equal(ID, node.encryptor.ID) )
					return node.encryptor;
			}
			return null;
		}
	}

	private static Handlers handlers = new Handlers();	
}
