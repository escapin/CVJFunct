package de.uni.trier.infsec.functionalities.pkenc.ideal;

import de.uni.trier.infsec.environment.crypto.CryptoLib;
import de.uni.trier.infsec.utils.MessageTools;

/**
 * Ideal functionality for public-key encryption: Encryptor
 */
public final class Encryptor {

	private MessagePairList log;
	private byte[] publKey;
	
	Encryptor(MessagePairList mpl, byte[] publicKey) { 
		log = mpl;		
		publKey = publicKey;
	}
		
	public byte[] getPublicKey() {
		return MessageTools.copyOf(publKey);
	}
	
	public byte[] encrypt(byte[] message) {
		byte[] messageCopy = MessageTools.copyOf(message);
		byte[] randomCipher = MessageTools.copyOf(CryptoLib.encrypt(MessageTools.getZeroMessage(1), 
																	MessageTools.copyOf(publKey))); // Note the fixed size (1) of a message
		if( randomCipher == null ) return null;
		log.add(messageCopy, randomCipher);
		return MessageTools.copyOf(randomCipher);
	}
	
}
