package de.uni.trier.infsec.functionalities.pki.ideal;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for digital signatures with PKI (Public Key Infrastructure).
 *
 * The intended usage is as follows. An agent who wants to use this functionality to
 * sign messages must first register herself:
 *
 *     PKISig.Signer signer_of_A = PKISig.register(ID_OF_A);
 *
 *  Then, this agent can use this object to sign messages:
 *
 *     byte[] signature = signer_of_A.sign(message);
 *
 * Another agent can verify signatures generated by A as follows:
 *
 *     PKISig.Verifier verifier_for_A = getVerifier(ID_OF_A);
 *     boolean ok = verifier_for_A.verify(signature, message);
 *
 * Note using of the real crypto lib (not the one controlled by the environment)
 * in the implementation of this functionality.
 */
public class PKISig {

	/**
	 * An object encapsulating a verification key and allowing a user to verify
	 * signatures. In this ideal implementation, verification check whether the given
	 * pair message/signature has been registered in the log.
	 */
	static public class Verifier {
		private int ID;
		private byte[] verifKey;
		private Log log;

		private Verifier(int id, byte[] verifKey, Log log) {
			this.ID = id;
			this.verifKey = verifKey;
			this.log = log;
		}

		public boolean verify(byte[] signature, byte[] message) {
			// verify the signature using the (real) verification algorithm
			if( !CryptoLib.verify(message, signature, verifKey) )
				return false;
			// and check that the message has been logged as signed
			return log.contains(message);
		}

		public byte[] getVerifKey() {
			return copyOf(verifKey);
		}
	}

	/**
	 * An object encapsulating a signing/verification key pair and allowing a user to
	 * create a signature. In this implementation, when a message is signed, a real signature
	 * is created (by an algorithm provided in lib.crypto) an the pair message/signature
	 * is stores in the log.
	 */
	static public class Signer {
		private int ID;
		private byte[] verifKey;
		private byte[] signKey;
		private Log log;

		private Signer(int id) {
			KeyPair keypair = CryptoLib.generateSignatureKeyPair(); // note usage of the real cryto lib here
			this.signKey = copyOf(keypair.privateKey);
			this.verifKey = copyOf(keypair.publicKey);
			this.ID = id;
			this.log = new Log();
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey)); // note usage of the real crypto lib here
			// we make sure that the signing has not failed
			if (signature == null) return null; // FIXME: it should return something
			// and that the signature is correct
			if( !CryptoLib.verify(copyOf(message), copyOf(signature), copyOf(verifKey)) )
				return null; // FIXME: it should return something
			// now we log the message (only!) as signed and return the signature
			log.add(copyOf(message));
			return copyOf(copyOf(signature));
		}

		public Verifier getVerifier() {
			return new Verifier(ID, verifKey, log);
		}
	}

	public static Signer register(int id, byte[] smt_domain) {
		if( registeredAgents.fetch(id) != null ) return null; // a party with this id has already registered
		Signer signer = new Signer(id);
		Verifier verifier = signer.getVerifier();
		registeredAgents.add(verifier);
		return signer;
	}

	public static Verifier getVerifier(int id, byte[] smt_domain) {
		return registeredAgents.fetch(id);
	}


	/// IMPLEMENTATION ///

	private static class RegisteredAgents {
		private static class VerifierList {
			Verifier verifier;
			VerifierList  next;
			VerifierList(Verifier verifier, VerifierList next) {
				this.verifier= verifier;
				this.next = next;
			}
		}

		private VerifierList first = null;

		public void add(Verifier ver) {
			first = new VerifierList(ver, first);
		}

		Verifier fetch(int ID) {
			for( VerifierList node = first;  node != null;  node = node.next ) {
				if( ID == node.verifier.ID )
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
