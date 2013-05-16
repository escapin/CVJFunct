package de.uni.trier.infsec.functionalities.pki.idealcor;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for public-key encryption with PKI (Public Key Infrastructure)
 * and with static corruption.
 */
public class PKIEnc {

	/// The public interface ///

	static public class Encryptor {
		public final int id;
		protected byte[] publicKey;

		public Encryptor(int id, byte[] publicKey) {
			this.id = id;
			this.publicKey = publicKey;
		}

		public byte[] encrypt(byte[] message) {
			return copyOf(CryptoLib.pke_encrypt(copyOf(message), copyOf(publicKey)));
		}

		public byte[] getPublicKey() {
			return copyOf(publicKey);
		}
	}

	// This class is not in the public interface of the corresponding real functionality
	static public final class UncorruptedEncryptor extends Encryptor {
		private EncryptionLog log;

		private UncorruptedEncryptor(int id, byte[] publicKey, EncryptionLog log) {
			super(id, publicKey);
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
	}

	static public class Decryptor {
		public int ID;
		private byte[] publicKey;
		private byte[] privateKey;
		private EncryptionLog log;

		public Decryptor(int id) {
			KeyPair keypair = CryptoLib.pke_generateKeyPair();
			this.privateKey = copyOf(keypair.privateKey);
			this.publicKey = copyOf(keypair.publicKey);
			this.ID = id;
			this.log = new EncryptionLog();
		}

		public byte[] decrypt(byte[] message) {
			byte[] messageCopy = copyOf(message);
			if (!log.containsCiphertext(messageCopy)) {
				return copyOf( CryptoLib.pke_decrypt(copyOf(privateKey), messageCopy) );
			} else {
				return copyOf( log.lookup(messageCopy) );
			}
		}

		// Returns a new uncorrupted encryptor object sharing the same public key, ID, and log.
		public Encryptor getEncryptor() {
			return new UncorruptedEncryptor(ID, publicKey, log);
		}
	}

	// FIXME: pki_domain is ignored in the methods below
	public static void register(Encryptor encryptor, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		if( registeredAgents.fetch(encryptor.id) != null ) // encryptor.id is registered?
			throw new PKIError();
		registeredAgents.add(encryptor);
	}

	public static Encryptor getEncryptor(int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		PKIEnc.Encryptor enc = registeredAgents.fetch(id);
		if (enc == null)
			throw new PKIError();
		return enc;
	}

	/// IMPLEMENTATION ///

	private static class RegisteredAgents {
		private static class EncryptorList {
			PKIEnc.Encryptor encryptor;
			EncryptorList  next;
			EncryptorList(PKIEnc.Encryptor encryptor, EncryptorList next) {
				this.encryptor= encryptor;
				this.next = next;
			}
		}

		private EncryptorList first = null;

		public void add(PKIEnc.Encryptor encr) {
			first = new EncryptorList(encr, first);
		}

		PKIEnc.Encryptor fetch(int ID) {
			for( EncryptorList node = first;  node != null;  node = node.next ) {
				if( ID == node.encryptor.id )
					return node.encryptor;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();

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
}
