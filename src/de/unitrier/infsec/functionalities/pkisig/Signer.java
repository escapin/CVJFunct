package de.unitrier.infsec.functionalities.pkisig;

import static de.unitrier.infsec.utils.MessageTools.copyOf;
import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;
import de.unitrier.infsec.utils.MessageTools;

/**
 * An object encapsulating a signing/verification key pair and allowing a user to
 * create a signature. In this implementation, when a message is signed, a real signature
 * is created (by an algorithm provided in lib.crypto) an the pair message/signature
 * is stores in the log.
 */
final public class Signer {
	private byte[] verifKey;
	private byte[] signKey;
	private Log log;

	public Signer() {
		KeyPair keypair = CryptoLib.generateSignatureKeyPair();
		this.signKey = copyOf(keypair.privateKey);
		this.verifKey = copyOf(keypair.publicKey);
		this.log = new Log();
	}

	public byte[] sign(byte[] message) {
		byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey));
		// we make sure that the signing has not failed
		if (signature == null) return null;
		// and that the signature is correct
		if( !CryptoLib.verify(copyOf(message), copyOf(signature), copyOf(verifKey)) )
			return null;
		// now we log the message (only!) as signed and return the signature
		log.add(copyOf(message));
		return copyOf(copyOf(signature));
	}

	public Verifier getVerifier() {
		return new UncorruptedVerifier(verifKey, log);
	}
	
	///// IMPLEMENTATION /////
	
	static class Log {

		private static class MessageList {
			byte[] message;
			MessageList next;
			public MessageList(byte[] message, MessageList next) {
				this.message = message;
				this.next = next;
			}
		}

		private MessageList first = null;

		public void add(byte[] message) {
			first = new MessageList(message, first);
		}

		boolean contains(byte[] message) {
			for( MessageList node = first;  node != null;  node = node.next ) {
				if( MessageTools.equal(node.message, message) )
					return true;
			}
			return false;
		}
	}
	
}
