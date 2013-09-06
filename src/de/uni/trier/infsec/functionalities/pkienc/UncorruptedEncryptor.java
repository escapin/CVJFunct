package de.uni.trier.infsec.functionalities.pkienc;

import static de.uni.trier.infsec.utils.MessageTools.copyOf;
import static de.uni.trier.infsec.utils.MessageTools.getZeroMessage;
import de.uni.trier.infsec.lib.crypto.CryptoLib;


/**
 * Uncorrupted encryptor.
 * The only way to obtain such an encryptor is through a decryptor.
 * This class is not in the public interface of the corresponding real functionality.
 */	
public final class UncorruptedEncryptor extends Encryptor {
	private Decryptor.EncryptionLog log;

	UncorruptedEncryptor(byte[] publicKey, Decryptor.EncryptionLog log) {
		super(publicKey);
		this.log = log;
	}

	public byte[] encrypt(byte[] message) {
		byte[] randomCipher = null;
		// keep asking the environment for the ciphertext, until a fresh one is given:
		while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
			randomCipher = copyOf(CryptoLib.pke_encrypt(getZeroMessage(message.length), copyOf(publicKey)));
		}
		log.add(copyOf(message), randomCipher);
		return copyOf(randomCipher);
	}

	protected Encryptor copy() {
		return new UncorruptedEncryptor(publicKey, log);
	}
}	

