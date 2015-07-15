package de.unitrier.infsec.functionalities.pkenc;

import static de.unitrier.infsec.utils.MessageTools.copyOf;
import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;
import de.unitrier.infsec.utils.MessageTools;


/**
 * Ideal functionality for public-key encryption: Decryptor
 */
public final class Decryptor {
	
	private byte[] privateKey; 
	private byte[] publicKey;
	private EncryptionLog log;

	public Decryptor() {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		publicKey = copyOf(keypair.publicKey);  
		privateKey = copyOf(keypair.privateKey); 
		log = new EncryptionLog();
	}

	
	public byte[] decrypt(byte[] message) {
		byte[] messageCopy = copyOf(message); 
		if (!log.containsCiphertext(messageCopy)) {
			return copyOf( CryptoLib.pke_decrypt(copyOf(privateKey), messageCopy) );
		} else {
			return copyOf( log.lookup(messageCopy) );
		}
	}
	
	public Encryptor getEncryptor() {
        return new Encryptor(publicKey, log);
    }
	
	///// IMPLEMENTATION //////
	
	static class EncryptionLog {

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
}
