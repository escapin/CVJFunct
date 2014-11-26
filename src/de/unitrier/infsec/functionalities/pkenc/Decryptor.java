package de.unitrier.infsec.functionalities.pkenc;

import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;
import static de.unitrier.infsec.utils.MessageTools.copyOf;

// THIS FUNCTIONALITY IS OBSOLETE. USE PKI INSTEAD.

/**
 * Ideal functionality for public-key encryption: Decryptor
 */
public final class Decryptor {
	
	private byte[] privKey; 
	private byte[] publKey;
	private MessagePairList log = new MessagePairList();

	public Decryptor() {
		KeyPair keypair = CryptoLib.pke_generateKeyPair();
		publKey = copyOf(keypair.publicKey);  
		privKey = copyOf(keypair.privateKey); 
	}

    public Encryptor getEncryptor() {
        return new Encryptor(log,publKey);
    }

	public byte[] decrypt(byte[] message) {
		byte[] messageCopy = copyOf(message); 
		if (!log.contains(messageCopy)) {
			return copyOf( CryptoLib.pke_decrypt(copyOf(privKey), messageCopy) );
		} else {
			return copyOf( log.lookup(messageCopy) );
		}
	}
}
