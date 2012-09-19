package de.uni.trier.infsec.protocols.simplevoting;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.functionalities.pkenc.real.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.real.Encryptor;
import de.uni.trier.infsec.lib.network.Network;
import de.uni.trier.infsec.protocols.simplevoting.voterGUI.VotingClientDialog;
import de.uni.trier.infsec.utils.Utilities;

public class VoterStandalone {

	public String publicKeyPath = null;
	public String privateKeyPath = null;
	private byte[] voterID = null;

	public static final byte REQUEST_CREDENTIAL = 0x01;
	public static final byte SUBMIT_BALLOT = 0x02;
	public static final byte SUBMIT_RESULT = 0x03;
	public static final byte ERROR_WRONG_PHASE = 0x04;
	public static final byte ERROR_NO_ERROR = 0x00;

	private int serverPort = Network.DEFAULT_PORT;
	private String serverAddress = Network.DEFAULT_SERVER;

	/*
	 * With this version, voterID is supposed to be a string
	 */
	public static void main(String[] args) {
		if (args.length < 3) {
			System.out.println("Parameters missing. Usage: VoterStandalone <path-to-publickey> <path-to-privatekey> <voterID>");
			System.exit(0);
		}
		VoterStandalone handler;
		if (args.length >= 5) {
			handler = new VoterStandalone(args[0], args[1], args[2], args[3], Integer.parseInt(args[4])); // public key, private key, voter ID, Votingserver address, Votingserver Port 
		} else {
			handler = new VoterStandalone(args[0], args[1], args[2]); // public key, private key, voter ID
		}
		VotingClientDialog window = new VotingClientDialog(handler);
		window.showWindow();
	}

	public VoterStandalone(String publicKeyPath, String privateKeyPath, String voterID) {
		this.publicKeyPath = publicKeyPath;
		this.privateKeyPath = privateKeyPath;
		this.voterID = voterID.getBytes();
	}

	public VoterStandalone(String publicKeyPath, String privateKeyPath, String voterID, String serverAddress, int serverPort) {
		this(publicKeyPath, privateKeyPath, voterID);
		System.out.println(String.format("VotingClient started using parameters publicKeyPath: %s, privateKeyPath: %s, serverAddress: %s, serverPort: %d",
				publicKeyPath, privateKeyPath, serverAddress, serverPort));
		this.serverAddress = serverAddress;
		this.serverPort = serverPort;
	}

	public void clickVote(byte choice) throws IOException {
		Encryptor encServer = new Encryptor(Utilities.hexStringToByteArray(VotingServerStandalone.publicKey));
		Decryptor decClient = new Decryptor(readVoterPublicKeyFromFile(), readVoterPrivateKeyFromFile());
		Voter voter = new Voter(voterID, decClient, encServer);
		String filename = System.getProperty("java.io.tmpdir") + File.separator + "evoting" + File.separator
				+ Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode()) + ".evo";
		File f = new File(filename);
		if (f.exists()) {
			FileInputStream fis = new FileInputStream(f);
			byte[] credential = new byte[fis.available()];
			fis.read(credential);
			voter.setCredential(credential);
			byte[] ballot = voter.makeBallot(choice);
			sendBallotToServer(ballot);
		}
	}

	/**
	 * Sends a message which has following format: 0x01 | ballot
	 */
	private void sendBallotToServer(byte[] ballot) {
		byte[] message = new byte[ballot.length + 1];
		message[0] = SUBMIT_BALLOT;
		System.arraycopy(ballot, 0, message, 1, ballot.length);
		try {
			Network.connectToServer(serverAddress, serverPort);
			Network.networkOut(message);
			byte[] response = Network.networkIn();
			if (response[0] == ERROR_WRONG_PHASE) {
				throw new IllegalStateException("Server not in ballot collection phase!");
			}
		} catch (NetworkError e) {
			throw new IllegalStateException("Server not available or connection problems!");
		} finally {
			Network.resetConnection();
		}
	}

	public String clickRegister() throws IOException, NetworkError {
		System.out.println("using voter id " + Utilities.byteArrayToHexString(voterID));
		byte[] message = new byte[voterID.length + 1];
		byte[] response = null;
		message[0] = REQUEST_CREDENTIAL;
		System.arraycopy(voterID, 0, message, 1, voterID.length);

		try {
			if (!Network.connectToServer(serverAddress, serverPort)) {
				throw new IllegalStateException("Server not available or connection problems!");
			}
			Network.networkOut(message);
			byte[] in = Network.networkIn();
			if (in != null)
				System.out.println("received: " + Utilities.byteArrayToHexString(in));
			if (in != null && in[0] == ERROR_NO_ERROR) {
				response = new byte[in.length - 1];
				for (int i = 0; i < response.length; i++)
					response[i] = in[i + 1];
			} else if (in == null || in[0] == ERROR_WRONG_PHASE) {
				throw new IllegalStateException("Server not in registration phase!");
			}
		} catch (NetworkError e) {
			throw new IllegalStateException("Server not available or connection problems!");
		} finally {
			Network.resetConnection();
		}

		Encryptor encServer = new Encryptor(Utilities.hexStringToByteArray(VotingServerStandalone.publicKey));
		Decryptor decClient = new Decryptor(readVoterPublicKeyFromFile(), readVoterPrivateKeyFromFile());
		Voter voter = new Voter(voterID, decClient, encServer);
		voter.setCredential(response);

		new File(System.getProperty("java.io.tmpdir") + File.separator + "evoting").mkdirs();
		FileOutputStream fout = new FileOutputStream(System.getProperty("java.io.tmpdir") + File.separator + "evoting" + File.separator
				+ Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode()) + ".evo");
		fout.write(response);
		fout.close();

		return Utilities.byteArrayToHexString(response);
	}

	/**
	 * Checks whether a exists that contains the credential.
	 */
	public boolean isRegistered() {
		String filename = System.getProperty("java.io.tmpdir") + File.separator + "evoting" + File.separator
				+ Integer.toString(Utilities.byteArrayToHexString(readVoterPublicKeyFromFile()).hashCode()) + ".evo";
		if ((new File(filename)).exists()) {
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
