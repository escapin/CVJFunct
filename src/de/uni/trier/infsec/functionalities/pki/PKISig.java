package de.uni.trier.infsec.functionalities.pki;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.lib.network.NetworkError;


/**
 * Real functionality for digital signatures with PKI (Public Key Infrastructure).
 *
 * For intended usage see class ...ideal.PKISig.
 */
public class PKISig {

	public static final byte[] DOMAIN_VERIFICATION  = new byte[] {0x04, 0x01};
	
	/**
	 * An object encapsulating the verification key and allowing a user to verify
	 * a signature.
	 */
	static public class Verifier {
		private byte[] verifKey;

		public Verifier(byte[] verifKey) {
			this.verifKey = verifKey;
		}

		public boolean verify(byte[] signature, byte[] message) {
			return CryptoLib.verify(copyOf(message), copyOf(signature), copyOf(verifKey));
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

		public Signer() {
			KeyPair keypair = CryptoLib.generateSignatureKeyPair();
			this.signKey = copyOf(keypair.privateKey);
			this.verifKey = copyOf(keypair.publicKey);
		}

		private Signer(byte[] verifKey, byte[] signKey ) {
			this.verifKey = verifKey;
			this.signKey = signKey;
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey));
			return copyOf(signature);
		}

		public Verifier getVerifier() {
			return new Verifier(verifKey);
		}
	}

	public static void registerVerifier(PKISig.Verifier verifier, int id, byte[] pki_domain) throws PKIError, NetworkError {
		PKI.register(id, pki_domain, verifier.getVerifKey());
	}

	public static PKISig.Verifier getVerifier(int id, byte[] pki_domain) throws PKIError, NetworkError {
		byte[] key = PKI.getKey(id, pki_domain);
		return new PKISig.Verifier(key);
	}

	public static byte[] signerToBytes(Signer signer) {
		byte[] out = concatenate(signer.signKey, signer.verifKey);
		return out;
	}

	public static Signer signerFromBytes(byte[] bytes) {
		byte[] sign_key = first(bytes);
		byte[] verif_key = second(bytes);
		return new Signer(verif_key, sign_key);
	}
}
