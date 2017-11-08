package funct.pki;

import static utils.MessageTools.byteArrayToInt;
import static utils.MessageTools.concatenate;
import static utils.MessageTools.first;
import static utils.MessageTools.intToByteArray;
import static utils.MessageTools.second;
import static utils.Utilities.arrayEqual;

import funct.pki.PKIServerApp.PKIMessage;
import lib.crypto.CryptoLib;
import lib.network.NetworkClient;
import lib.network.NetworkError;
import utils.MessageTools;
import utils.Utilities;


public class PKIServerRemote implements PKIServer {

	@Override
	public void register(int id, byte[] domain, byte[] pubKey) throws PKI.Error, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServerApp.MSG_REGISTER;
		request.nonce = CryptoLib.nextNonce();
		request.domain = domain;
		request.payload = concatenate(intToByteArray(id), pubKey);

		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServerApp.HOSTNAME, PKIServerApp.LISTEN_PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);

		// Verify Signature first!
		if (!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServerApp.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}

		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServerApp.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKI.Error();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServerApp.MSG_ERROR_NETWORK)) {
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
	public byte[] getKey(int id, byte[] domain) throws PKI.Error, NetworkError {
		PKIMessage request = new PKIMessage();
		request.request = PKIServerApp.MSG_GET_KEY;
		request.nonce = CryptoLib.nextNonce();
		request.domain = domain;
		request.payload = MessageTools.intToByteArray(id);

		byte[] response = NetworkClient.sendRequest(PKIMessage.toBytes(request), PKIServerApp.HOSTNAME, PKIServerApp.LISTEN_PORT);
		PKIMessage responseMsg = PKIMessage.fromBytes(response);

		// Verify Signature
		if(!CryptoLib.verify(responseMsg.bytesForSign(), responseMsg.signature, Utilities.hexStringToByteArray(PKIServerApp.VerificationKey))) {
			echo("Signature verification failed!");
			throw new NetworkError();
		}

		// Verify Nonce
		if (!Utilities.arrayEqual(responseMsg.nonce, request.nonce)) {
			echo("Nonce verification failed!");
			throw new NetworkError();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServerApp.MSG_ERROR_PKI)) {
			echo("Server responded with PKI error");
			throw new PKI.Error();
		}

		if (Utilities.arrayEqual(responseMsg.payload, PKIServerApp.MSG_ERROR_NETWORK)) {
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

	void echo(String txt) {
		//		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + this.getClass().getSimpleName() + "] " + txt);
	}
}
