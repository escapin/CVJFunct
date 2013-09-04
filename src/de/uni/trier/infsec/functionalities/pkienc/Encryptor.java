package de.uni.trier.infsec.functionalities.pkienc;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import de.uni.trier.infsec.lib.crypto.CryptoLib;


/** Encryptor encapsulating possibly corrupted public key.
 */
public class Encryptor {
	protected byte[] publicKey;

	public Encryptor(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public byte[] encrypt(byte[] message) {
		return copyOf(CryptoLib.pke_encrypt(copyOf(message), copyOf(publicKey)));
	}

	public byte[] getPublicKey() {
		return copyOf(publicKey);
	}

	protected Encryptor copy() {
		return new Encryptor(publicKey);
	}	
}

