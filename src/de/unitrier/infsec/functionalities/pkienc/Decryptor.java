package de.unitrier.infsec.functionalities.pkienc;

import static de.unitrier.infsec.utils.MessageTools.copyOf;
import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;
import de.unitrier.infsec.utils.MessageTools;


/** An object encapsulating the private and public keys of some party. */
public class Decryptor {
	private byte[] publicKey;
	private byte[] privateKey;
	private EncryptionLog log;

	public Decryptor() {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		this.privateKey = copyOf(keypair.privateKey);
		this.publicKey = copyOf(keypair.publicKey);
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

	/** Returns a new uncorrupted encryptor object sharing the same public key, ID, and log. */
	public Encryptor getEncryptor() {
		return new UncorruptedEncryptor(publicKey, log);
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
