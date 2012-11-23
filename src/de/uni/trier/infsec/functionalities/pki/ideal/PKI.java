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
	
	static public class Decryptor {
		private byte[] ID;
		private byte[] publicKey;
		private byte[] privateKey;
		private MessagePairList log;

		private Decryptor(byte[] id) {
			KeyPair keypair = CryptoLib.generateKeyPair();
			byte[] privKey = copyOf(keypair.privateKey);
			byte[] publKey = copyOf(keypair.publicKey);
			this.ID = id;
			this.publicKey = publKey;
			this.privateKey = privKey;
			this.log = null;
		}
		
		private byte[] encrypt(byte[] message) {
			byte[] messageCopy = copyOf(message);
			byte[] randomCipher = null;
			// keep asking the environment for the ciphertext, until a fresh one is given:
			while( randomCipher==null || log.contains(randomCipher) ) {
				randomCipher = copyOf(CryptoLib.pke_encrypt(getZeroMessage(message.length), copyOf(publicKey)));
			}
			log.add(messageCopy, randomCipher);
			return copyOf(randomCipher);
		}
		
		public byte[] decrypt(byte[] message) {
			byte[] messageCopy = copyOf(message); 
			if (!log.contains(messageCopy)) {
				return copyOf( CryptoLib.pke_decrypt(copyOf(privateKey), messageCopy) );
			} else {
				return copyOf( log.lookup(messageCopy) );
			}			
		}
	}

	public static Decryptor register(byte[] id) {
		id = copyOf(id);
		if( handlers.fetch(id) != null ) return null; // a party with this id has already registered
		Decryptor pki = new Decryptor(id);
		handlers = new DecrList(pki, handlers);
		return pki;
	}
	
	public static byte[] encryptFor(byte[] id, byte[] message) {
		// fetch the handler to the PKIIdeal object with given id
		Decryptor handle = handlers.fetch(id);
		if( handle==null ) return null;
		// encrypt 'message' using this handle
		return copyOf(handle.encrypt(message));
	}
	
	public static byte[] getPublicKey(byte[] id) {
		Decryptor handle = handlers.fetch(id);
		return copyOf(handle.publicKey);
	}
	

	
/// Implementation ///
	
	private static class DecrList {	
		Decryptor handle;
		DecrList next;
	
		DecrList(Decryptor handle, DecrList next) {
			this.handle = handle;
			this.next = next;
		}
		
		Decryptor fetch(byte[] ID) {
			for( DecrList node = this;  node!=null;  node = node.next ) {
				if( equal(ID, node.handle.ID) )
					return node.handle;
			}
			return null;
		}
	}
	
	private static class MessagePair {
		byte[] ciphertext;
		byte[] plaintext;
		MessagePair next;
		public MessagePair(byte[] ciphertext, byte[] plaintext, MessagePair next) {
			this.ciphertext = ciphertext;
			this.plaintext = plaintext;
			this.next = next;
		}
	}
	
	private static class MessagePairList {
		private MessagePair first = null;
		
		public void add(byte[] pTxt, byte[] cTxt) {
			first = new MessagePair(cTxt, pTxt, first);
		}

	    byte[] lookup(byte[] ciphertext) {
	        MessagePair tmp = first;
	        while( tmp != null ) {
	            if( MessageTools.equal(tmp.ciphertext, ciphertext) )
	                return tmp.plaintext;
	            tmp = tmp.next;
	        }
	        return null;
	    }
	    
	    boolean contains(byte[] ciphertext) {
	    	return lookup(ciphertext) != null;
	    }    
	}
	
	private static DecrList handlers = null;	

}
