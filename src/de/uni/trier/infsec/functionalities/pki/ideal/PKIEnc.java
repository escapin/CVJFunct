package de.uni.trier.infsec.functionalities.pki.ideal;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for public-key encryption with PKI (Public Key Infrastructure).
 * 
 * The intended usage is as follows.
 * 
 * An honest party A creates her decryptor, encryptor and registers in the following way:
 *
 *		PKIEnc.Decryptor dec_a = new PKIEnc.Decryptor(ID_A);
 *		PKIEnc.Encryptor enc_a = dec_a.getEncryptor(); // enc_a is an uncorrupted encryptor 
 *		try {
 *			PKIEnc.register(enc_a, PKI_DOMAIN);
 *		}
 *		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
 *		catch (NetworkError e) {} // or we have not got any answer
 *
 * A decryptor can be used to decrypt messages (encrypted for A).
 * 
 * To encrypt something for A, one does the following:
 * 
 *		try {
 *			PKIEnc.Encryptor encryptor_of_a = PKIEnc.getEncryptor(ID_A, PKI_DOMAIN);
 *			encryptor_of_a.encrypt(message1);
 *		}
 *		catch(PKIError e) {} // if ID_A has not been successfully registered, we land here
 *		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
 */
public class PKIEnc {
	
/// The public interface ///

	/** An object encapsulating the public key of some party.
	 *  
	 *  This key can be accessed directly of indirectly via method encrypt.
	 *  Method encrypt realizes the "ideal" encryption, where a string of 
	 *  zeros is encrypted instead of the original message and the pair 
	 *  (plaintext, ciphertest) is stored in a log which can be then used
	 *  for decryption.    
	 */
	static public class Encryptor {
		public final int id;	
		private byte[] publicKey;
		private EncryptionLog log;

		// note that the constructor is not public; encryptors are only created from decryptors
		Encryptor(int id, byte[] publicKey, EncryptionLog log) {
			this.id = id;
			this.publicKey = publicKey;
			this.log = log;
		}
		
		public byte[] encrypt(byte[] message) {
			byte[] randomCipher = null;
			// keep asking the environment for the ciphertext, until a fresh one is given:
			while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
				randomCipher = copyOf(CryptoLib.pke_encrypt(getZeroMessage(message.length), copyOf(publicKey)));
				// TODO: make sure that the order of arguments (to encrypt) is correct
			}
			log.add(copyOf(message), randomCipher);
			return copyOf(randomCipher);
		}

		public byte[] getPublicKey() {
			return copyOf(publicKey);
		}

		private Encryptor copy() {
			return new Encryptor(id, publicKey, log);
		}
	}
	
	/** An object encapsulating the private and public keys of some party. */
	static public class Decryptor {
		public final int id;
		private byte[] publicKey;
		private byte[] privateKey;
		private EncryptionLog log;

		public Decryptor(int id) {
			KeyPair keypair = CryptoLib.pke_generateKeyPair();
			this.privateKey = copyOf(keypair.privateKey);
			this.publicKey = copyOf(keypair.publicKey);
			this.id = id;
			this.log = new EncryptionLog();
		}		
		
		/** "Decrypts" a message by, first trying to find in in the log (and returning
		 *   the related plaintext) and, only if this fails, by using real decryption. */
		public byte[] decrypt(byte[] message) {
			byte[] messageCopy = copyOf(message); 
			if (!log.containsCiphertext(messageCopy)) {
				return copyOf( CryptoLib.pke_decrypt(copyOf(privateKey), messageCopy) );
				// TODO: make sure that the order of arguments is correct
			} else {
				return copyOf( log.lookup(messageCopy) );
			}			
		}
		
		/** Returns a new encryptor object sharing the same public key, ID, and log. */
		public Encryptor getEncryptor() {
			return new Encryptor(id, publicKey, log);
		}	
	}

	// TODO: pki_domain is ignored in the methods below
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
		return enc.copy();
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
