package de.uni.trier.infsec.functionalities.pki.real;

import java.io.Serializable;

public class SignedMessage implements Serializable {
	public final byte[] message;
	public final byte[] signature;
	
	public SignedMessage(byte[] message, byte[] signature) {
		this.message = message;
		this.signature = signature;
	}
}
