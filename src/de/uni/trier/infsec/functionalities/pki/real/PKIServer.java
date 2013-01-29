package de.uni.trier.infsec.functionalities.pki.real;

import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.network.NetworkServer;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;


/**
 *	PKIServer enables Remote Procedure Calls for PKI. In order to run it, simply start this 
 *  server and set property on the client side:
 *	-Dremotemode=true
 *	Every server response is a pair <m, signature(m)> which will be validated before processing.
 *	In order to use encrypted communication for PKIServer, refer to this manual to enable SSL/TLS:
 *  https://blogs.oracle.com/lmalventosa/entry/using_the_ssl_tls_based
 *  For now, we use unencrypted communication only.
 */

public class PKIServer {
	public static final String  VerificationKey = "30819F300D06092A864886F70D010101050003818D0030818902818100962A84DBCDBAE0E4EA433B5D3819AE0031F269A14425B5037827429D48BD5FA5089D49D2D4DD87BB24D73A66334388992CA96D85317E55C50083542A5946B290134CA18B1AFB9C441E9ED97F06ADE0FDAB2F1056EE9251B8688A0C831C310FE0B680C912D4D9EFB34A3FC6461CB190C50BCF503CF331DF52E4A6AEB0A1A628A50203010001";
	private static final String SigningKey 		= "30820277020100300D06092A864886F70D0101010500048202613082025D02010002818100962A84DBCDBAE0E4EA433B5D3819AE0031F269A14425B5037827429D48BD5FA5089D49D2D4DD87BB24D73A66334388992CA96D85317E55C50083542A5946B290134CA18B1AFB9C441E9ED97F06ADE0FDAB2F1056EE9251B8688A0C831C310FE0B680C912D4D9EFB34A3FC6461CB190C50BCF503CF331DF52E4A6AEB0A1A628A502030100010281800D3056D2E752CE85CC7D732D50CC10983BCACAB43B44048DF5739D4A2B2556CD2BE084A75BC2C9350A9B4CA9C53EDD3476D3BAA6C41E107269051FD3485C093AB3A89CABC31C4F116D74194D7C746FC1B1228B03C0C0FD687FB7DB5A6FBCC4F48C12829FC1610490EDA9195A775D50D2CEB802A6FD361F867145B2254F2C8701024100D4D5F19451F04FD1FCDAE98F3496547554DF89A4827F207A7D990472302EC5EEB259613E4F8D2DF309B38805A6FF5658A21920B918FDFAC9C0552EE0BBB19A15024100B49EE0DEC743100F5F9B6E5AA9445EE5297814BCEDBB640E30A9BC000FCD6BDDB0950CFFEDB18A564D443CAB86402F635C3E65A43C885CF322B60A15EEC4C851024100D12C268DA76DEF74A7F619DEE546ED6096F64E9740AD62252034F79AA5E202235262E7604EDCA8911832BA771BA60C9D754A0ECFFB50F95DB8C9BF159D41B1F5024057C32B389451BDA7FAA8A7825DE4DEC732D32A2072D32ED6C64673170496A7E6DC3A504ABAD01D8BB997827345944272610BE08F60EA515FC269F99496A3FF41024100AE2556E61D42665444125FF641B46A524BD4A9993BFAE04598A93041CC536075C74464AEE64B37B3FDBC1325F6E93733EC2BBDAEFAC1CD04B54C1072724D7CC0";
	
	public static final String 	HOSTNAME = "localhost";
	public static final int 	PORT = NetworkServer.LISTEN_PORT;

	protected PKIServer() {
	}

	public static void main(String[] args) throws Exception {
		new PKIServer().run();
	}
	
	public void run() throws Exception {
		// Busy waiting - not a nice solution at all, but should be ok for now. 
		while(true) {
			byte[] request = NetworkServer.nextRequest();
			if (request != null) {
				byte[] response = handleRequest(request);
				NetworkServer.response(response);
			} else {				
				Thread.sleep(500);
			}
		}
	}
	
	
	private byte[] handleRequest(byte[] request) {
		echo("Received Request: 0x" + Utilities.byteArrayToHexString(request));
		byte[] requestType = MessageTools.first(request);
		byte[] requestMsg  = MessageTools.second(request);
		echo("Request type: 0x" + Utilities.byteArrayToHexString(requestType));
		
		if (Utilities.arrayEqual(requestType, PKIServerInterface.MSG_GET_PUBLIC_KEY)) {
			echo("Request is: Get public Key");
			byte[] pubKey = PKIServerCore.pki_getPublicKey(MessageTools.byteArrayToInt(requestMsg));
			echo("Public key is: " + Utilities.byteArrayToHexString(pubKey));
			
			byte[] response = MessageTools.concatenate(requestMsg, pubKey);
			echo("Response is: " + Utilities.byteArrayToHexString(requestType));
			
			byte[] signature = CryptoLib.sign(response, Utilities.hexStringToByteArray(SigningKey));
			echo("Signature is: " + Utilities.byteArrayToHexString(requestType));
			
			byte[] out = MessageTools.concatenate(signature, response);
			echo("Responding Request: 0x" + Utilities.byteArrayToHexString(out));
			return out;
		} else if (Utilities.arrayEqual(requestType, PKIServerInterface.MSG_REGISTER)) {
			echo("Request is: Register");
			byte[] id  = MessageTools.first(requestMsg);
			byte[] pubKey = MessageTools.second(requestMsg);
			echo("Request ID is: " + Utilities.byteArrayToHexString(id));
			echo("Public key is: " + Utilities.byteArrayToHexString(pubKey));
			
			if (PKIServerCore.pki_register(MessageTools.byteArrayToInt(id), pubKey)) {
				echo("[PKIServer] Successfully registered Public key");

				byte[] response = MessageTools.concatenate(id, pubKey);
				echo("Response is: " + Utilities.byteArrayToHexString(response));
				
				byte[] signature = CryptoLib.sign(response, Utilities.hexStringToByteArray(SigningKey));
				echo("Signature is: " + Utilities.byteArrayToHexString(signature));
				
				byte[] out = MessageTools.concatenate(signature, response);
				echo("Responding Request: 0x" + Utilities.byteArrayToHexString(out));
				return out;
			} else {
				echo("Could not register public key!");

				byte[] signature = CryptoLib.sign(PKIServerInterface.MSG_ERROR_REGISTRATION, Utilities.hexStringToByteArray(SigningKey));
				echo("Signature is: " + Utilities.byteArrayToHexString(signature));
				
				byte[] out = MessageTools.concatenate(signature, PKIServerInterface.MSG_ERROR_REGISTRATION);
				echo("Responding Request: 0x" + Utilities.byteArrayToHexString(out));
				return out;
			}
		}
		echo("Request unknown. Returning null");
		return null; // TODO Perhaps send response "UNKNOWN_REQUEST"?
		// TODO: in the case the id is registered, it should return (signed) response which explicitly says that.
	}
	
	void echo(String txt) {
		if (!Boolean.parseBoolean(System.getProperty("DEBUG"))) return;
		System.out.println("[" + this.getClass().getSimpleName() + "] " + txt);
	}
	
}
