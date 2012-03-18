package de.uni.trier.infsec.crypto.real.objects.key;

import javax.crypto.spec.SecretKeySpec;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;


/**
 * Wrapper for java.security.Key
 */
public class SymmetricKey {
	private java.security.Key theKey = null;
	
	public SymmetricKey(java.security.Key key) {
		this.theKey = key;
	}
	
	public SymmetricKey(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid SymmetricKey - Wrong TAG!");
		}
		this.theKey = new SecretKeySpec(m.getBytesWOTag(), RealLibrary.AES256_CBC_MODE);
	}
	
	public java.security.Key getKey() {
		return theKey;
	}
	
	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(this.theKey.getEncoded(), Message.TAG_KEY);
		return m;
	}
	
}
