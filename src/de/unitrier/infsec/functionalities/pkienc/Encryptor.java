package de.unitrier.infsec.functionalities.pkienc;

import de.unitrier.infsec.utils.MessageTools;
import de.unitrier.infsec.lib.crypto.CryptoLib;


/** Encryptor encapsulating possibly corrupted public key.
 */
public class Encryptor {
	protected byte[] publicKey;

	public Encryptor(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public byte[] encrypt(byte[] message) {
		return MessageTools.copyOf(CryptoLib.pke_encrypt(MessageTools.copyOf(message), MessageTools.copyOf(publicKey)));
	}

	public byte[] getPublicKey() {
		return MessageTools.copyOf(publicKey);
	}

	protected Encryptor copy() {
		return new Encryptor(publicKey);
	}	
}

