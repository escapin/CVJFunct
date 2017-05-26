package functionalities.digsig;

import lib.crypto.CryptoLib;
import utils.MessageTools;

/**
 * An object encapsulating the verification key and allowing a user to verify
 * a signature.
 */
public class Verifier {
	
	private byte[] verifKey;
	private Signer.Log log;
	
	// Note that this constructor is not public in the ideal functionality.
	public Verifier(byte[] verifKey, Signer.Log log) {
		this.verifKey = verifKey;
		this.log = log;
	}

	public boolean verify(byte[] signature, byte[] message) {
		// verify both that the signature is correct (using the real verification 
		// algorithm) and that the message has been logged as signed
		return CryptoLib.verify(MessageTools.copyOf(message), MessageTools.copyOf(signature), MessageTools.copyOf(verifKey))
				&& log.contains(message);
	}

	public byte[] getVerificationKey() {
		return MessageTools.copyOf(verifKey);
	}
}