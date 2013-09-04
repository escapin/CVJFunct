package de.uni.trier.infsec.functionalities.pkisig;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;

public class Verifier {
	protected byte[] verifKey;

	public Verifier(byte[] verifKey) {
		this.verifKey = verifKey;
	}

	public boolean verify(byte[] signature, byte[] message) {
		return CryptoLib.verify(message, signature, verifKey);
	}

	public byte[] getVerifKey() {
		return copyOf(verifKey);
	}

	protected Verifier copy() {
		return new Verifier(verifKey);
	}
}
