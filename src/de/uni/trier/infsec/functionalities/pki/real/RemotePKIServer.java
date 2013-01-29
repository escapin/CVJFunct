package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;


public class RemotePKIServer implements PKIServerInterface {

	@Override
	public SignedMessage register(int id, byte[] pubKey) throws NetworkError {
		byte[] message = null;
		// message = <MSG_REGISTER, <id,pubKey> >
		echo("Requesting registration for: ID=" + id + ", PK=" + Utilities.byteArrayToHexString(pubKey));
		
		echo("id as byte: " + Utilities.byteArrayToHexString(MessageTools.intToByteArray(id)));
		echo("id check: " + MessageTools.byteArrayToInt(MessageTools.intToByteArray(id)));
		
		message = MessageTools.concatenate(MSG_REGISTER, MessageTools.concatenate(MessageTools.intToByteArray(id), pubKey));
		echo("Sending message: " + Utilities.byteArrayToHexString(message));
		
		byte[] response = NetworkClient.sendRequest(message, PKIServer.HOSTNAME, PKIServer.PORT);
		
		byte[] signature = MessageTools.first(response);
		byte[] data = MessageTools.second(response);
		
		// Verify Signature first!
		if (!CryptoLib.verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			System.out.println("Signature verification failed!");
			return null;
		}
		
		if (Utilities.arrayEqual(data, PKIServerInterface.MSG_ERROR_REGISTRATION)) {
			System.out.println("Server responded with registration error");
			return null;
		}
		return new SignedMessage(data, signature);
	}

	@Override
	public SignedMessage getPublicKey(int id) throws NetworkError {
		byte[] message = null;
		// message = <MSG_REGISTER, id >
		message = MessageTools.concatenate(MSG_GET_PUBLIC_KEY, MessageTools.intToByteArray(id));
		echo("Sending message: " + Utilities.byteArrayToHexString(message));		
		
		byte[] response = NetworkClient.sendRequest(message, PKIServer.HOSTNAME, PKIServer.PORT);
		echo("Received response: " + Utilities.byteArrayToHexString(response));
		
		byte[] signature = MessageTools.first(response);
		byte[] data = MessageTools.second(response);
		
		// Verify Signature
		if(!CryptoLib.verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			System.out.println("Signature verification failed!");
			return null;
		}
		
		return new SignedMessage(data, signature);
	}

	@Override
	public void test() {
		// TODO Same here - what should happen in this function?
	}
	
	void echo(String txt) {
		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + this.getClass().getSimpleName() + "] " + txt);
	}

}
