package de.uni.trier.infsec.crypto.real.objects.key;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.objects.Message;

/**
 * Wrapper for RSAPrivateKey
 */
public class DecryptionKey {
	private RSAPrivateKey privateKey = null;
	
	public DecryptionKey(RSAPrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	public DecryptionKey(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid DecryptionKey - Wrong TAG!");
		}
		
		byte[] key = m.getBytesWOTag();
		
		KeyFactory rsaKeyFac;
		try {
			rsaKeyFac = KeyFactory.getInstance("RSA", "BC");
			PKCS8EncodedKeySpec encodedPrivKeySpec = new PKCS8EncodedKeySpec(key);  
			this.privateKey = (RSAPrivateKey) rsaKeyFac.generatePrivate(encodedPrivKeySpec);
		} catch (Exception e) {
			throw new CryptoException(e);
		}  
	}

	public RSAPrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public String toString() {
		String s = "";
		s += "\tLength: " + privateKey.getPrivateExponent().bitLength() + " Bits,\tContent: " + privateKey.getPrivateExponent() + " mod (Length: " + privateKey.getModulus().bitCount() + "Bits) " + privateKey.getModulus();
		return s;
	}
	
	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(this.privateKey.getEncoded(), Message.TAG_KEY);
		return m;
	}

}
