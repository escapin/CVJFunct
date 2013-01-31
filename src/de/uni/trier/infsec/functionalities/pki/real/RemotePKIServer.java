package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.byteArrayToInt;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.intToByteArray;
import static de.uni.trier.infsec.utils.Utilities.arrayEqual;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;


public class RemotePKIServer implements PKIServerInterface {

	@Override
	public void register(int id, byte[] pubKey) throws PKIError, NetworkError {
		byte[] message = null;
		// message = <MSG_REGISTER, <id,pubKey> >
		echo("Requesting registration for: ID=" + id + ", PK=" + Utilities.byteArrayToHexString(pubKey));
		
		echo("id as byte: " + Utilities.byteArrayToHexString(intToByteArray(id)));
		echo("id check: " + byteArrayToInt(intToByteArray(id)));
		
		message = MessageTools.concatenate(PKIServer.MSG_REGISTER, concatenate(intToByteArray(id), pubKey));
		echo("Sending message: " + Utilities.byteArrayToHexString(message));
		
		byte[] response = NetworkClient.sendRequest(message, PKIServer.HOSTNAME, PKIServer.PORT);
		
		byte[] signature = MessageTools.first(response);
		byte[] data = MessageTools.second(response);
		
		// Verify Signature first!
		if (!CryptoLib.verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			System.out.println("Signature verification failed!");
			throw new PKIError();
		}
		
		if (Utilities.arrayEqual(data, PKIServer.MSG_ERROR_REGISTRATION)) {
			System.out.println("Server responded with registration error");
			throw new PKIError();
		}
		
		int id_from_data = byteArrayToInt(first(data));
		byte[] pk_from_data = second(data);
		
		if (id != id_from_data) {
			System.out.println("ID in response message is not equal to expected id: \nReceived: " +  id + "\nExpected: " + id_from_data);
			throw new PKIError();
		}
		
		if (!arrayEqual(pk_from_data, pubKey)) {
			System.out.println("PK in response message is not equal to expected id: \nReceived: " + Utilities.byteArrayToHexString(pk_from_data) + "\nExpected: " + Utilities.byteArrayToHexString(pubKey));
			throw new PKIError();
		}
	}

	@Override
	public byte[] getPublicKey(int id) throws PKIError, NetworkError {
		byte[] message = null;
		// message = <MSG_REGISTER, id >
		message = MessageTools.concatenate(PKIServer.MSG_GET_PUBLIC_KEY, MessageTools.intToByteArray(id));
		echo("Sending message: " + Utilities.byteArrayToHexString(message));		
		
		byte[] response = NetworkClient.sendRequest(message, PKIServer.HOSTNAME, PKIServer.PORT);
	
		echo("Received response: " + Utilities.byteArrayToHexString(response));
		
		byte[] signature = MessageTools.first(response);
		byte[] data = MessageTools.second(response);
		
		// Verify Signature
		if(!CryptoLib.verify(data, signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			System.out.println("Signature verification failed!");
			throw new PKIError();
		}
		
		int id_from_data = byteArrayToInt(first(data));
		byte[] publKey = second(data);
		
		// Verify that the response message contains the correct id
		if (id != id_from_data) {
			System.out.println("ID in response message is not equal to expected id: \nReceived: " + id + "\nExpected: " + id_from_data);
			throw new PKIError();
		}

		return publKey;
	}

	void echo(String txt) {
		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + this.getClass().getSimpleName() + "] " + txt);
	}

}
