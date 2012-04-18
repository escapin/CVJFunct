package de.uni.trier.infsec.protocols.simplevoting;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.real.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.real.Encryptor;
import de.uni.trier.infsec.lib.network.Network;
import de.uni.trier.infsec.protocols.simplevoting.voterGUI.VotingClientDialog;
import de.uni.trier.infsec.utils.Utilities;

public class VoterStandalone {

	private String publicKeyPath  = null;
	private String privateKeyPath = null;

	public static void main(String[] args) {
		if (args.length < 2) {
			System.out.println("Parameters missing. Usage: VoterStandalone <path-to-publickey> <path-to-privatekey>");
			System.exit(0);
		}
		VoterStandalone handler = new VoterStandalone(args[0], args[1]);
		VotingClientDialog window = new VotingClientDialog(handler);
		window.showWindow();
	}
	
	
	public VoterStandalone(String publicKeyPath, String privateKeyPath) {
		this.publicKeyPath = publicKeyPath;
		this.privateKeyPath = privateKeyPath;
	}
	
	public String clickVote(String selectedValue) {
		Encryptor encServer = new Encryptor(Utilities.hexStringToByteArray(VotingServerStandalone.publicKey));
		Decryptor decClient = new Decryptor(readVoterPublicKeyFromFile(), readVoterPrivateKeyFromFile());
		Voter voter = new Voter(decClient, encServer);
		byte[] ballot = voter.makeBallot(Utilities.hexStringToByteArray(selectedValue)[0]);
		
		return sendBallotToServer(ballot);
	}

	/**
	 * Sends a message which has following format:
	 * 		0x01 | ballot
	 */
	private String sendBallotToServer(byte[] ballot) {
		byte[] message = new byte[ballot.length + 1];
		message[0] = 0x01;
		System.arraycopy(ballot, 0, message, 1, ballot.length);
		try {
			Network.connectToServer(Network.DEFAULT_SERVER, Network.DEFAULT_PORT);
			Network.networkOut(message);
		} catch (NetworkError e) {
			return e.getLocalizedMessage();
		} finally {
			Network.disconnect();
		}
		return null;
	}


	public String clickRegister() throws IOException, NetworkError {
		byte[] pubKey = readVoterPublicKeyFromFile();
		System.out.println("using public key " + Utilities.byteArrayToHexString(pubKey));
		byte[] message = new byte[pubKey.length + 1];
		byte[] response = null;
		message[0] = 0x02;
		System.arraycopy(pubKey, 0, message, 1, pubKey.length);
		
		try {
			Network.connectToServer(Network.DEFAULT_SERVER, Network.DEFAULT_PORT);
			Network.networkOut(message);
			response = Network.networkIn();
		} catch (NetworkError e) {
			throw e;
		} finally {
			Network.disconnect();
		}
		
		Encryptor encServer = new Encryptor(Utilities.hexStringToByteArray(VotingServerStandalone.publicKey));
		Decryptor decClient = new Decryptor(readVoterPublicKeyFromFile(), readVoterPrivateKeyFromFile());
		Voter voter = new Voter(decClient, encServer);
		voter.setCredential(response);
		
		FileOutputStream fout = new FileOutputStream(System.getProperty("java.io.tmpdir") + "/" + Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode()) + ".evo");
		fout.write(response);
		fout.close();

		return Utilities.byteArrayToHexString(response);
	}

	/**
	 * Checks whether a exists that contains the credential.
	 */
	public boolean isRegistered() {
		String filename = System.getProperty("java.io.tmpdir") + "/" + Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode()) + ".evo";
		if ((new File (filename)).exists()) {			
			return true;
		}
		return false;
	}
	
	public byte[] readVoterPublicKeyFromFile() {
		try {
			FileInputStream fis = new FileInputStream(publicKeyPath);
			byte[] out = new byte[fis.available()];
			fis.read(out);
			return out;
		} catch (IOException e) {
			return null;
		}
	}

	public byte[] readVoterPrivateKeyFromFile() {
		try {
			FileInputStream fis = new FileInputStream(privateKeyPath);
			byte[] out = new byte[fis.available()];
			fis.read(out);
			return out;
		} catch (IOException e) {
			return null;
		}
	}
	
	public byte[] readCredentialFromFile() {
		try {
			String filename = "./" + Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode());
			FileInputStream fis = new FileInputStream(filename);
			byte[] out = new byte[fis.available()];
			fis.read(out);
			return out;
		} catch (IOException e) {
			return null;
		}
	}


}
