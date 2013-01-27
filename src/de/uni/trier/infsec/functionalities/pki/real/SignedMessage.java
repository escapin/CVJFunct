package de.uni.trier.infsec.functionalities.pki.real;

public class SignedMessage {
	public final byte[] message;
	public final byte[] signature;
	
	public SignedMessage(byte[] message, byte[] signature) {
		this.message = message;
		this.signature = signature;
	}
}
