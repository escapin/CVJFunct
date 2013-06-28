package de.uni.trier.infsec.functionalities.pki.idealcor;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for digital signatures with PKI (Public Key Infrastructure).
 *
 * The intended usage is as follows.
 *
 * An honest agent who wants to use this functionality to sign messages must first
 * create her signer object, then obtain a related verifier, and register it:
 *
 *		PKISig.Signer sig_a = new PKISig.Signer(ID_A);
 *		PKISig.Verifier verif_a = sig_a.getVerifier(); // verif_a is an uncorrupted verifier
 *		try {
 *			PKISig.register(verif_a, PKI_DOMAIN);
 *		}
 *		catch (PKIError e) {}     // registration failed: the identifier has been already claimed.
 *		catch (NetworkError e) {} // or we have not got any answer
 *
 * A signer can be used to sign messages.
 * 
 * For a corrupted party B, a (corrupted) verifier can be obtained directly:
 *
 *		PKISig.Verifier verif_b = new PKISig.Verifier(ID_A, verif_key);
 *		// register verif_b as above
 *
 * Now, to verify a signature of, one does the following:
 *
 *		try {
 *			PKISig.Verifier verif_of_a = PKISig.getVerifier(ID_A, PKI_DOMAIN);
 *			verif_of_a.verify(signature1, message1);
 *		}
 *		catch(PKIError e) {} // if ID_A has not been successfully registered, we land here
 *		catch(NetworkError e) {} // or here, if there has been no (or wrong) answer from PKI
 *
 * To make the fact (or assumption) that the verifier is uncorrupted explicit we cast it to
 * UncorruptedVerifier (only possible for the ideal functionalities):
 *
 *	 	PKISig.UncorruptedVerifier uncorrupted_verif_of_a = (PKISig.UncorruptedVerifier) verif_of_a;
 *
 * Note that an exception is thrown if this assumption is false.
 */
public class PKISig {

	static public class Verifier {
		public final int id;
		protected byte[] verifKey;

		public Verifier(int id, byte[] verifKey) {
			this.id = id;
			this.verifKey = verifKey;
		}

		public boolean verify(byte[] signature, byte[] message) {
			return CryptoLib.verify(message, signature, verifKey);
		}

		public byte[] getVerifKey() {
			return copyOf(verifKey);
		}

		protected Verifier copy() {
			return new Verifier(id, verifKey);
		}
	}

	static public final class UncorruptedVerifier extends Verifier {
		private Log log;

		private UncorruptedVerifier(int id, byte[] verifKey, Log log) {
			super(id,verifKey);
			this.log = log;
		}

		public boolean verify(byte[] signature, byte[] message) {
			// verify both that the signature is correc (using the real verification 
			// algorithm) and that the message has been logged as signed
			return CryptoLib.verify(message, signature, verifKey) && log.contains(message);
		}

		protected Verifier copy() {
			return new UncorruptedVerifier(id, verifKey, log);
		}
	}

	/**
	 * An object encapsulating a signing/verification key pair and allowing a user to
	 * create a signature. In this implementation, when a message is signed, a real signature
	 * is created (by an algorithm provided in lib.crypto) an the pair message/signature
	 * is stores in the log.
	 */
	static final public class Signer {
		public final int id;
		private byte[] verifKey;
		private byte[] signKey;
		private Log log;

		public Signer(int id) {
			KeyPair keypair = CryptoLib.generateSignatureKeyPair(); // note usage of the real cryto lib here
			this.signKey = copyOf(keypair.privateKey);
			this.verifKey = copyOf(keypair.publicKey);
			this.id = id;
			this.log = new Log();
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey)); // note usage of the real crypto lib here
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
			return new UncorruptedVerifier(id, verifKey, log);
		}
	}

	// FIXME: pki_domain is ignored in the methods below
	public static void register(Verifier verifier, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		if( registeredAgents.fetch(verifier.id) != null ) // verified.ID is registered?
			throw new PKIError();
		registeredAgents.add(verifier);
	}

	public static Verifier getVerifier(int id, byte[] pki_domain) throws PKIError, NetworkError {
		if( Environment.untrustedInput() == 0 ) throw new NetworkError();
		Verifier verif = registeredAgents.fetch(id);
		if (verif == null)
			throw new PKIError();
		return verif.copy();
	}

	/// IMPLEMENTATION ///

	private static class RegisteredAgents {
		private static class VerifierList {
			PKISig.Verifier verifier;
			VerifierList  next;
			VerifierList(PKISig.Verifier verifier, VerifierList next) {
				this.verifier = verifier;
				this.next = next;
			}
		}

		private VerifierList first = null;

		public void add(PKISig.Verifier verif) {
			first = new VerifierList(verif, first);
		}

		PKISig.Verifier fetch(int ID) {
			for( VerifierList node = first;  node != null;  node = node.next ) {
				if( ID == node.verifier.id )
					return node.verifier;
			}
			return null;
		}
	}

	private static RegisteredAgents registeredAgents = new RegisteredAgents();

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
}
