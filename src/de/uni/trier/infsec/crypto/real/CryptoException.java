package de.uni.trier.infsec.crypto.real;

public class CryptoException extends Exception {

	private static final long serialVersionUID = 1L;

	public CryptoException(String message) {
		super(message);
	}
	
	public CryptoException(Throwable cause) {
		super(cause);
	}

}
