package de.uni.trier.infsec.crypto.real.objects.key;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.objects.Message;

/**
 * Wrapper for RSAPrivateKey
 */
public class VerificationKey {
	public VerificationKey(RSAPrivateKey private1) {
	}


	private RSAPublicKey publicKey = null;

	public VerificationKey(RSAPublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public VerificationKey(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid VerificationKey - Wrong TAG!");
		}
		byte[] key = m.getBytesWOTag();
		KeyFactory rsaKeyFac;
		try {
			rsaKeyFac = KeyFactory.getInstance("RSA", "BC");
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
			this.publicKey = (RSAPublicKey) rsaKeyFac.generatePublic(keySpec);
		} catch (Exception e) {
			throw new CryptoException(e);
		}
	}

	public RSAPublicKey getPublicKey() {
		return publicKey;
	}
	
	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(this.publicKey.getEncoded(), Message.TAG_KEY);
		return m;
	}

	@Override
	public String toString() {
		String s = "";
		s += "\tLength: " + publicKey.getPublicExponent().bitLength() + " Bits,\tContent: " + publicKey.getPublicExponent() + " mod (Length: "
				+ publicKey.getModulus().bitCount() + "Bits) " + publicKey.getModulus();
		return s;
	}
}
