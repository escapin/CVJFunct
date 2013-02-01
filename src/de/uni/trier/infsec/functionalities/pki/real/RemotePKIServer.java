package de.uni.trier.infsec.functionalities.pki.real;

import static de.uni.trier.infsec.utils.MessageTools.byteArrayToInt;
import static de.uni.trier.infsec.utils.MessageTools.first;
import static de.uni.trier.infsec.utils.MessageTools.second;
import static de.uni.trier.infsec.utils.MessageTools.concatenate;
import static de.uni.trier.infsec.utils.MessageTools.intToByteArray;
import static de.uni.trier.infsec.utils.Utilities.arrayEqual;
import de.uni.trier.infsec.functionalities.pki.real.PKIServer.PKIMessage;
import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;


public class RemotePKIServer implements PKIServerInterface {

	@Override
	public void registerPublicKey(int id, byte[] pubKey) throws PKIError, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServer.MSG_REGISTER;
		request.nonce = CryptoLib.generateNonce();
		request.payload = concatenate(intToByteArray(id), pubKey);
		
		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServer.HOSTNAME, PKIServer.PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);
		
		// Verify Signature first!
		if (!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}
		
		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKIError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_NETWORK)) {
			echo("Server responded with Network error");
			throw new NetworkError();
		}
		
		int id_from_data = byteArrayToInt(first(responseMsg.payload));
		byte[] pk_from_data = second(responseMsg.payload);
		
		if (id != id_from_data) {
			echo("ID in response message is not equal to expected id: \nReceived: " +  id + "\nExpected: " + id_from_data);
			throw new NetworkError();
		}
		
		if (!arrayEqual(pk_from_data, pubKey)) {
			echo("PK in response message is not equal to expected id: \nReceived: " + Utilities.byteArrayToHexString(pk_from_data) + "\nExpected: " + Utilities.byteArrayToHexString(pubKey));
			throw new NetworkError();
		}
	}

	@Override
	public byte[] getPublicKey(int id) throws PKIError, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServer.MSG_GET_PUBLIC_KEY;
		request.nonce = CryptoLib.generateNonce();
		request.payload = MessageTools.intToByteArray(id);
		
		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServer.HOSTNAME, PKIServer.PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);
	
		// Verify Signature
		if(!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}
		
		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKIError();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_NETWORK)) {
			echo("Server responded with Network error");
			throw new NetworkError();
		}
		
		int id_from_data = byteArrayToInt(first(responseMsg.payload));
		byte[] publKey = second(responseMsg.payload);
		
		// Verify that the response message contains the correct id
		if (id != id_from_data) {
			echo("ID in response message is not equal to expected id: \nReceived: " + id + "\nExpected: " + id_from_data);
			throw new NetworkError();
		}

		return publKey;
	}

	@Override
	public void registerVerificationKey(int id, byte[] verKey) throws PKIError, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServer.MSG_REGISTER_SIGNATUREKEY;
		request.nonce = CryptoLib.generateNonce();
		request.payload = concatenate(intToByteArray(id), verKey);
		
		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServer.HOSTNAME, PKIServer.PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);
		
		// Verify Signature first!
		if (!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}
		
		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKIError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_NETWORK)) {
			echo("Server responded with Network error");
			throw new NetworkError();
		}
		
		int id_from_data = byteArrayToInt(first(responseMsg.payload));
		byte[] pk_from_data = second(responseMsg.payload);
		
		if (id != id_from_data) {
			echo("ID in response message is not equal to expected id: \nReceived: " +  id + "\nExpected: " + id_from_data);
			throw new NetworkError();
		}
		
		if (!arrayEqual(pk_from_data, verKey)) {
			echo("Verificationkey in response message is not equal to expected id: \nReceived: " + Utilities.byteArrayToHexString(pk_from_data) + "\nExpected: " + Utilities.byteArrayToHexString(verKey));
			throw new NetworkError();
		}
	}

	@Override
	public byte[] getVerificationKey(int id) throws PKIError, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServer.MSG_GET_VERIFICATION_KEY;
		request.nonce = CryptoLib.generateNonce();
		request.payload = MessageTools.intToByteArray(id);
		
		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServer.HOSTNAME, PKIServer.PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);
	
		// Verify Signature
		if(!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServer.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}
		
		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}
		
		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKIError();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServer.MSG_ERROR_NETWORK)) {
			echo("Server responded with Network error");
			throw new NetworkError();
		}
		
		int id_from_data = byteArrayToInt(first(responseMsg.payload));
		byte[] verificationKey = second(responseMsg.payload);
		
		// Verify that the response message contains the correct id
		if (id != id_from_data) {
			echo("ID in response message is not equal to expected id: \nReceived: " + id + "\nExpected: " + id_from_data);
			throw new NetworkError();
		}

		return verificationKey;
	}
	
	
	void echo(String txt) {
		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + this.getClass().getSimpleName() + "] " + txt);
	}


}
