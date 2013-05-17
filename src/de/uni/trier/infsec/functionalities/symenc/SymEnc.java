package de.uni.trier.infsec.functionalities.symenc;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.utils.MessageTools;

public class SymEnc {

	private byte[] key;
	private EncryptionLog log;
	
	public SymEnc() {
		key = CryptoLib.symkey_generateKey();
	}
	
	public byte[] encrypt(byte[] plaintext) {
		byte[] randomCipher = null;
		// keep asking the environment for the ciphertext, until a fresh one is given:
		while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
			randomCipher = copyOf(CryptoLib.symkey_encrypt(copyOf(key), getZeroMessage(plaintext.length)));
		}
		log.add(copyOf(plaintext), randomCipher);
		return copyOf(randomCipher);		
	}
	
	public byte[] decrypt(byte[] ciphertext) { 
		if (!log.containsCiphertext(ciphertext)) {
			return copyOf( CryptoLib.symkey_decrypt(copyOf(key), copyOf(ciphertext)) );
		} else {
			return copyOf( log.lookup(ciphertext) );
		}			
	}
	
	/// IMPLEMENTATION ///
	
	private static class EncryptionLog {

		private static class MessagePairList {
			byte[] plaintext;
			byte[] ciphertext;
			MessagePairList next;
			public MessagePairList(byte[] plaintext, byte[] ciphertext, MessagePairList next) {
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
