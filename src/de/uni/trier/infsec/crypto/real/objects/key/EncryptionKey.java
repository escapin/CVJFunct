package de.uni.trier.infsec.crypto.real.objects.key;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.objects.Message;

/**
 * Wrapper for RSAPublicKey
 */
public class EncryptionKey {
	private RSAPublicKey publicKey = null;
	
	public EncryptionKey(RSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	public EncryptionKey(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid EncryptionKey - Wrong TAG!");
		}
		
		byte[] key = m.getBytesWOTag();
		KeyFactory rsaKeyFac;
		try {
			rsaKeyFac = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);  
			this.publicKey = (RSAPublicKey)rsaKeyFac.generatePublic(keySpec);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}
	
	public RSAPublicKey getPublicKey() {
		return publicKey;
	}
	
	@Override
	public String toString() {
		String s = "";
		s += "\tLength: " + publicKey.getPublicExponent().bitLength() + " Bits,\tContent: " + publicKey.getPublicExponent() + " mod (Length: " + publicKey.getModulus().bitCount() + "Bits) " + publicKey.getModulus();
		return s;
	}
	
	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(this.publicKey.getEncoded(), Message.TAG_KEY);
		return m;
	}

}
