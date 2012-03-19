package de.uni.trier.infsec.simpleprotocol;

import de.uni.trier.infsec.pkenc.ideal.Encryptor;

import de.uni.trier.infsec.untrusted.network.Network;
import de.uni.trier.infsec.untrusted.network.NetworkError;


final public class Client {
	private Encryptor BobPKE;
	private byte[] message;

	public Client(Encryptor BobPKE, byte message) {
		this.BobPKE = BobPKE;
		this.message = new byte[] {message}; 
	}

	public void onInit() throws NetworkError {
		byte[] encMessage = BobPKE.encrypt(message);
		Network.networkOut(encMessage);
	}
}
