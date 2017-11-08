package funct.nonce;

import lib.crypto.CryptoLib;
import utils.MessageTools;

/**
 * Ideal functionality for nonce generation. Nonces are supposed to be unuque
 * (but not necessarily unguessable).
 */
public class NonceGen {

	public NonceGen() {
	}

	public byte[] nextNonce() {
		byte[] nonce = null;
		// keep asking for a nonce until we get a fresh value
		while( nonce==null || log.contains(nonce) ) {
			nonce = CryptoLib.nextNonce();
		}
		// we have a fresh nonce; add it to the log and return
		log.add(nonce);
		return nonce;
	}

	/// IMPLEMENTATION ///
	private static class Log {

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

	private static Log log; // note that this log is static => global nonce freshness
}
