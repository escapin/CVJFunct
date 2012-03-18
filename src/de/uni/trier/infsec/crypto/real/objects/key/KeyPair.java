package de.uni.trier.infsec.crypto.real.objects.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;

/**
 *
 * Wrapper class for a public / private keypair.
 */
public class KeyPair {
	private EncryptionKey thePublicKey = null;
	private DecryptionKey thePrivateKey = null;
	
	public KeyPair(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid KeyPair - Wrong TAG!");
		}
		Message mPrivKey = RealLibrary.project0(m);
		Message mPubKey  = RealLibrary.project1(m);
		
		this.thePrivateKey = new DecryptionKey(mPrivKey);
		this.thePublicKey  = new EncryptionKey(mPubKey);
	}
	
	public KeyPair(DecryptionKey dec, EncryptionKey enc) {
		this.thePrivateKey = dec;
		this.thePublicKey  = enc;
	}
	
	public KeyPair(java.security.KeyPair kp) {
		this.thePrivateKey = new DecryptionKey((RSAPrivateKey) kp.getPrivate());
		this.thePublicKey = new EncryptionKey((RSAPublicKey) kp.getPublic());
	}
	
	public EncryptionKey getEncryptionKey() {
		return thePublicKey;
	}

	public DecryptionKey getDecryptionKey() {
		return thePrivateKey;
	}

	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(RealLibrary.concatenate(this.thePrivateKey.toMessage(), this.thePublicKey.toMessage()).getBytes(), Message.TAG_KEY);
		return m;
	}
	
}
