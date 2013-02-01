package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.KeyPair;
import de.uni.trier.infsec.lib.network.NetworkError;


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

		private Signer() {
			KeyPair keypair = CryptoLib.generateSignatureKeyPair();
			this.signKey = copyOf(keypair.privateKey);
			this.verifKey = copyOf(keypair.publicKey);
		}

		public byte[] sign(byte[] message) {
			byte[] signature = CryptoLib.sign(copyOf(message), copyOf(signKey));
			return copyOf(signature);
		}

		public Verifier getVerifier() {
			return new Verifier(verifKey);
		}
	}

	public static Signer register(int id) throws NetworkError, PKIError {
		Signer signer = new Signer();
		pki_server.registerVerificationKey(id, copyOf(signer.verifKey));		
		return signer;
	}

	public static Verifier getVerifier(int id) throws NetworkError, PKIError {
		byte[] verKey = pki_server.getVerificationKey(id);		
		return new Verifier(verKey);
	}
	
	private static boolean remoteMode = Boolean.parseBoolean(System.getProperty("remotemode"));
	private static PKIServerInterface pki_server = null;
	static {
		if(remoteMode) {
			pki_server = new RemotePKIServer();
			System.out.println("Working in remote mode");
		}
		else {
			pki_server = new PKIServerCore();
			System.out.println("Working in local mode");
		}
	}
		
}
