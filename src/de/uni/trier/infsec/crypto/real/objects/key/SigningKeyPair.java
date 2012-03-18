package de.uni.trier.infsec.crypto.real.objects.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import de.uni.trier.infsec.crypto.real.CryptoException;
import de.uni.trier.infsec.crypto.real.RealLibrary;
import de.uni.trier.infsec.crypto.real.objects.Message;

public class SigningKeyPair {
	private SigningKey 		theSigningKey 		= null;
	private VerificationKey theVerificytionKey 	= null;
	
	public SigningKeyPair(Message m) throws CryptoException {
		if (m.getTag() != Message.TAG_KEY) {
			throw new CryptoException("Message seems not to be a valid SignatureKeyPair - Wrong TAG!");
		}
		Message mSignKey = RealLibrary.project0(m);
		Message mVeriKey = RealLibrary.project1(m);
		
		this.theSigningKey 		= new SigningKey(mSignKey);
		this.theVerificytionKey = new VerificationKey(mVeriKey);
	}
	
	public SigningKeyPair(SigningKey sign, VerificationKey verify) {
		this.theSigningKey = sign;
		this.theVerificytionKey = verify;
	}
	
	public SigningKeyPair(java.security.KeyPair kp) {
		this.theSigningKey 		= new SigningKey((RSAPrivateKey) kp.getPrivate());
		this.theVerificytionKey = new VerificationKey((RSAPublicKey) kp.getPublic());
	}
	
	public SigningKey getSigningKey() {
		return theSigningKey;
	}

	public VerificationKey getVerificationKey() {
		return theVerificytionKey;
	}
	
	public Message toMessage() {
		Message m = new Message();
		m.setBytesAndTag(RealLibrary.concatenate(theSigningKey.toMessage(), theVerificytionKey.toMessage()).getBytes(), Message.TAG_KEY);
		return m;
	}

	
}
