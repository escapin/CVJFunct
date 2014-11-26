package de.unitrier.infsec.functionalities.pkisig;

import de.unitrier.infsec.lib.crypto.CryptoLib;

public final class UncorruptedVerifier extends Verifier {
	private Signer.Log log;

	UncorruptedVerifier(byte[] verifKey, Signer.Log log) {
		super(verifKey);
		this.log = log;
	}

	public boolean verify(byte[] signature, byte[] message) {
		// verify both that the signature is correct (using the real verification 
		// algorithm) and that the message has been logged as signed
		return CryptoLib.verify(message, signature, verifKey) && log.contains(message);
	}

	protected Verifier copy() {
		return new UncorruptedVerifier(verifKey, log);
	}
}
