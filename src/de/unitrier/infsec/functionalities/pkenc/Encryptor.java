package de.unitrier.infsec.functionalities.pkenc;

import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.utils.MessageTools;

/**
 * Ideal functionality for public-key encryption: Encryptor
 */
public final class Encryptor {

	private byte[] publKey;
	private Decryptor.EncryptionLog log;
	
	Encryptor(byte[] publicKey, Decryptor.EncryptionLog log) { 
		publKey = publicKey;
		this.log=log;
	}
		
	public byte[] getPublicKey() {
		return MessageTools.copyOf(publKey);
	}
	
	public byte[] encrypt(byte[] message) {
		byte[] messageCopy = MessageTools.copyOf(message);
		byte[] randomCipher = null;
		// keep asking the environment for the ciphertext, until a fresh one is given:
		while( randomCipher==null || log.containsCiphertext(randomCipher) ) {
			randomCipher = MessageTools.copyOf(CryptoLib.pke_encrypt(MessageTools.getZeroMessage(message.length), MessageTools.copyOf(publKey)));
		}
		log.add(messageCopy, randomCipher);
		return MessageTools.copyOf(randomCipher);
	}
}
