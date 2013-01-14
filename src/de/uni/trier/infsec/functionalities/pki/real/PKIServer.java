package de.uni.trier.infsec.functionalities.pki.real;

import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.server.UnicastRemoteObject;
import java.util.HashMap;

import de.uni.trier.infsec.lib.crypto.CryptoLib;
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

public class PKIServer extends UnicastRemoteObject implements PKIServerInterface {
	private static final long serialVersionUID = 4696749351792779919L; // Needed for RMI

	public static final String  VerificationKey = "30819F300D06092A864886F70D010101050003818D0030818902818100962A84DBCDBAE0E4EA433B5D3819AE0031F269A14425B5037827429D48BD5FA5089D49D2D4DD87BB24D73A66334388992CA96D85317E55C50083542A5946B290134CA18B1AFB9C441E9ED97F06ADE0FDAB2F1056EE9251B8688A0C831C310FE0B680C912D4D9EFB34A3FC6461CB190C50BCF503CF331DF52E4A6AEB0A1A628A50203010001";
	private static final String SigningKey 		= "30820277020100300D06092A864886F70D0101010500048202613082025D02010002818100962A84DBCDBAE0E4EA433B5D3819AE0031F269A14425B5037827429D48BD5FA5089D49D2D4DD87BB24D73A66334388992CA96D85317E55C50083542A5946B290134CA18B1AFB9C441E9ED97F06ADE0FDAB2F1056EE9251B8688A0C831C310FE0B680C912D4D9EFB34A3FC6461CB190C50BCF503CF331DF52E4A6AEB0A1A628A502030100010281800D3056D2E752CE85CC7D732D50CC10983BCACAB43B44048DF5739D4A2B2556CD2BE084A75BC2C9350A9B4CA9C53EDD3476D3BAA6C41E107269051FD3485C093AB3A89CABC31C4F116D74194D7C746FC1B1228B03C0C0FD687FB7DB5A6FBCC4F48C12829FC1610490EDA9195A775D50D2CEB802A6FD361F867145B2254F2C8701024100D4D5F19451F04FD1FCDAE98F3496547554DF89A4827F207A7D990472302EC5EEB259613E4F8D2DF309B38805A6FF5658A21920B918FDFAC9C0552EE0BBB19A15024100B49EE0DEC743100F5F9B6E5AA9445EE5297814BCEDBB640E30A9BC000FCD6BDDB0950CFFEDB18A564D443CAB86402F635C3E65A43C885CF322B60A15EEC4C851024100D12C268DA76DEF74A7F619DEE546ED6096F64E9740AD62252034F79AA5E202235262E7604EDCA8911832BA771BA60C9D754A0ECFFB50F95DB8C9BF159D41B1F5024057C32B389451BDA7FAA8A7825DE4DEC732D32A2072D32ED6C64673170496A7E6DC3A504ABAD01D8BB997827345944272610BE08F60EA515FC269F99496A3FF41024100AE2556E61D42665444125FF641B46A524BD4A9993BFAE04598A93041CC536075C74464AEE64B37B3FDBC1325F6E93733EC2BBDAEFAC1CD04B54C1072724D7CC0";

	public static final String 	HOSTNAME = "localhost";
	public static final int 	PORT = 2020;


	protected PKIServer() throws RemoteException {
		super();
	}

	@Override
	public SignedMessage register(byte[] id, byte[] pubKey) throws RemoteException {
		// byte[] data = PKIEnc.decryptorToBytes(PKIEnc.register(id));
		//
		// FIXME: this class should not refer to PKIEnc (PKIEnc is a peculiarity related to our functionalities,
		// while PKIServer may be used without using PKIEnc).
		// Maintaining registered agents should be done here. Also, this data (that is the registered users) should
		// have some persistency -- it should be stored in some database (something file-based, like for instance
		// sqlite would do).
		//
		// Temporarily, I put here this:
		if( !pki_register(id, pubKey) ) return null;
		// Signed confirmation
		byte[] data = MessageTools.concatenate(id, pubKey);
		byte[] signature = CryptoLib.sign(data, Utilities.hexStringToByteArray(SigningKey));
		return new SignedMessage(data, signature);
	}

	@Override
	public SignedMessage getPublicKey(byte[] id) throws RemoteException {
		// byte[] data = PKIEnc.getEncryptor(id).getPublicKey();
		// FIXME: as above. For now, I put this:
		byte[] pubKey = pki_getPublicKey(id);
		byte[] data = MessageTools.concatenate(id, pubKey);
		byte[] signature = CryptoLib.sign(data, Utilities.hexStringToByteArray(SigningKey));
		return new SignedMessage(data, signature);
	}
	
	public static void main(String[] args) throws RemoteException {
		PKIServerInterface instance = new PKIServer();
		
		// In case server property has been set, we register RMI server
		// Register RMI Server here, Default port 8661
		try {
			LocateRegistry.createRegistry(2020);
			String binding = "//" + HOSTNAME + ":" + PORT + "/server";
			Naming.rebind(binding, instance);
			
			System.out.println("Server registered successfully. Listening on " + binding);
		} catch (Exception e) {
			System.out.println("Error while registering RMI registry: " + e.getMessage());
		}
	}

	@Override
	public void test() throws RemoteException {
		System.out.println();
	}


	/// Implementation ///
	// FIXME: just for now -- needs to be changed, as discussed

	private static HashMap<String, byte[]> pkLst = new HashMap<>();

	private static boolean pki_register(byte[] id, byte[] pubKey) {
		// Key of the HashMap is not the id itself but its String (Hex) representation, because we´d need "array-Equal" for byte arrays.
		if (pkLst.containsKey(Utilities.byteArrayToHexString(id))) {
			return false;
		}
		pkLst.put(Utilities.byteArrayToHexString(id), pubKey);
		return true;
	}

	private static byte[] pki_getPublicKey(byte[] id) {
		return pkLst.get(Utilities.byteArrayToHexString(id));
	}
}
