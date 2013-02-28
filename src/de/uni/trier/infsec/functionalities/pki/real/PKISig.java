package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import static de.uni.trier.infsec.utils.MessageTools.intToByteArray;
import static de.uni.trier.infsec.utils.MessageTools.byteArrayToInt;
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
		public final int ID;
		private byte[] verifKey;

		Verifier(int id, byte[] verifKey) {
			this.ID = id;
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
		public final int ID;
		private byte[] verifKey;
		private byte[] signKey;

		private Signer(int id, byte[] verifKey, byte[] signKey) {
			this.ID = id;
			this.verifKey = verifKey;
			this.signKey = signKey;
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey));
			return copyOf(signature);
		}

		public Verifier getVerifier() {
			return new Verifier(ID, verifKey);
		}
	}

	public static Signer register(int id, byte[] domain) throws NetworkError, PKIError {		
		KeyPair keypair = CryptoLib.generateSignatureKeyPair();
		byte[] signKey = copyOf(keypair.privateKey);
		byte[] verifKey = copyOf(keypair.publicKey);
		Signer signer = new Signer(id, verifKey, signKey);
		Verifier verifier = signer.getVerifier();
		PKIForSig.register(verifier, domain);		
		return signer;
	}

	public static Verifier getVerifier(int id, byte[] domain) throws NetworkError, PKIError {
		return PKIForSig.getVerifier(id, domain);
	}
		
	public static byte[] signerToBytes(Signer signer) {
		byte[] id = intToByteArray(signer.ID);
        byte[] sign = signer.signKey;
        byte[] verify = signer.verifKey;

        byte[] out = concatenate(id, concatenate(sign, verify));
        return out;
	}
	
	public static Signer signerFromBytes(byte[] bytes) {
		int id = byteArrayToInt(first(bytes));
		byte[] rest = second(bytes);
        byte[] sign_key = first(rest);
        byte[] verif_key = second(rest);
        return new Signer(id, verif_key, sign_key);
	}		
}
