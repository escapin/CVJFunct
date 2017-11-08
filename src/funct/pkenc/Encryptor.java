package funct.pkenc;

import lib.crypto.CryptoLib;
import utils.MessageTools;

/**
 * Ideal functionality for public-key encryption: Encryptor
 */
public final class Encryptor {

	private byte[] publicKey;
	private Decryptor.EncryptionLog log;
	
	Encryptor(byte[] publicKey, Decryptor.EncryptionLog log) { 
		this.publicKey = publicKey;
		this.log=log;
	}
		
	public byte[] getPublicKey() {
		return MessageTools.copyOf(publicKey);
	}
	
	public byte[] encrypt(byte[] message) {
		byte[] randomCipher = null;
		// keep asking the environment for the ciphertext, until a fresh one is given:
		while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
			randomCipher = MessageTools.copyOf(CryptoLib.pke_encrypt(MessageTools.getZeroMessage(message.length), MessageTools.copyOf(publicKey)));
		}
		log.add(MessageTools.copyOf(message), randomCipher);
		return MessageTools.copyOf(randomCipher);
	}
}
