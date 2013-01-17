package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;

/**
 * Real functionality for digital signatures with PKI (Public Key Infrastructure).
 *
 * For intended usage see class ...ideal.PKISig.
 */
public class PKISig {

	/**
	 * An object encapsulating the verification key and allowing a user to verify
	 * a signature.
	 */
	static public class Verifier {
		private byte[] verifKey;

		private Verifier(byte[] verifKey) {
			this.verifKey = verifKey;
		}

		public boolean verify(byte[] signature, byte[] message) {
			return CryptoLib.verify(message, signature, verifKey);
		}

		public byte[] getVerifKey() {
			return copyOf(verifKey);
		}
	}

	/**
	 * An object encapsulating a signing/verification key pair and allowing a user to
	 * create signatures.
	 */
	static public class Signer {
		private byte[] verifKey;
		private byte[] signKey;

		private Signer() {
			KeyPair keypair = CryptoLib.generateSignatureKeyPair();
			this.signKey = copyOf(keypair.privateKey);
			this.verifKey = copyOf(keypair.publicKey);
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey));
			return copyOf(copyOf(signature));
		}

		public Verifier getVerifier() {
			return new Verifier(verifKey);
		}
	}

	public static Signer register(int id) {
		// TODO: implement
		return null;
	}

	public static Verifier getVerifier(int id) {
		// TODO: implement
		return null;
	}
}
