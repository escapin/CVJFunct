package de.uni.trier.infsec.protocols.simplevoting;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import de.uni.trier.infsec.functionalities.pkenc.real.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.real.Encryptor;
import de.uni.trier.infsec.protocols.simplevoting.voterGUI.VotingServerDialog;
import de.uni.trier.infsec.utils.Utilities;

public class VotingServerStandalone {

	public static final String[] votes = new String[] { "01", "02", "03", "04", "05" };

	public static final String publicKey = "30819F300D06092A864886F70D010101050003818D0030818902818100DAB82D01DAEDB88"
			+ "F350ADA267308AB7AD57A337E1D0E6466D16200EE7804C2229BD78B0235364CA3AC5DAD17FF57683810E1208D6D25B9E3977ECCD"
			+ "6DB0856889F7B01321A3748CE363495C63621DE4A8CBC0711D76E0A8C4E55272020A1F063678F9495E8C14577A04903F5D3E504B"
			+ "2855DE642931A41E205EB6240850B9BD30203010001";

	public static final String privateKey = "30820277020100300D06092A864886F70D0101010500048202613082025D020100028181"
			+ "00DAB82D01DAEDB88F350ADA267308AB7AD57A337E1D0E6466D16200EE7804C2229BD78B0235364CA3AC5DAD17FF57683810E120"
			+ "8D6D25B9E3977ECCD6DB0856889F7B01321A3748CE363495C63621DE4A8CBC0711D76E0A8C4E55272020A1F063678F9495E8C145"
			+ "77A04903F5D3E504B2855DE642931A41E205EB6240850B9BD3020301000102818100D6967A79E67CF36575AA170C40329263AA8D"
			+ "01764B35B2A5F9EA4875AF4523DF66BD1BC267C8C57A9403386F61F334EA450D4BADD6177C80E242E2E02DF7C944E3A01001636A"
			+ "C500982B4AFDE4F1EEC2C7BBB75C0C56FB6A9316B6BC9B3954E4F00E8086466622C37C522D547DF226C4C1F4570E0748968EC7E5"
			+ "F85B098753D1024100F190D0BAB4B84F7A80044DF1C6DB027B5CD0FB57287A1FB2AB14FB8E7C3FE74CBB76A3F76AD4721B8BB4A5"
			+ "6FAABCA2244EA711CC45652C9E9F9DB9088A66800B024100E7C9E2BE631A4035DBC3F74A12C60DB69CAD122C0D0C902EFA1B93ED"
			+ "96B608DB482BA6724F842A7A6B16B8BD6AE255597E3E5D5C6F5F221C1AF9ED5C3BF2485902405AB150FC57EF3EBFB2226B951360"
			+ "945CF66AEB823C8B252D7237CD7E203DE9BC1041A9ABB16B13702E12636E3A3ED9ED21AE6DEB303E9CF2ECE04D60DC7D41230240"
			+ "0433A0AC9AD74AFAAEF52A72694CB5CAEDA425842EE85F64BA9BED5E8D30D790420AA885C1F33F61E0B714BA3A49C80A4B438E25"
			+ "B2CF22AB27C2080F77F6B86102410088539B65FB126BCA6EBD597E351E97BCA196500AEC1F1263E852E5AFECECF4E4FEFEF7ED55"
			+ "07557C561CED4319639A59B77FC55C74A11B76BD40F1FDC7AFE560";

	/**
	 * Constants used for the network protocol.
	 */
	public static final byte REQUEST_CREDENTIAL = 0x01; // Request code for credentials C --> S
	public static final byte SUBMIT_BALLOT = 0x02; // Request code for ballot submission C --> S
	public static final byte ERROR_WRONG_PHASE = 0x04; // Acknowledge for submission in wrong server state S --> C
	public static final byte ERROR_NO_ERROR = 0x00; // Acknowledge for submission in correct server state S --> C
	public static final byte PUBLISH_RESULT = 0x05; // Submission code for result publication S --> BulletinBoard

	public static final int PHASE_REGISTRATION = 1;
	public static final int PHASE_COLLECT_BALLOT = 2;
	public static final int PHASE_COUNT_AND_SUBMIT = 3;

	private VotingServerCore serverCore = null;
	private String votersPublicKeysFile = null;
	private String votersIdsFile = null;

	private int listenPort = Network.DEFAULT_PORT;
	private String bulletinBoardAddress = Network.DEFAULT_SERVER;
	private int bulletinBoardPort = HTTPBulletinBoard.DEFAULT_BULLETIN_BOARD_PORT;


	public VotingServerStandalone(String pathPK, String pathID) {
		this.votersPublicKeysFile = pathPK;
		this.votersIdsFile = pathID;
		init();
	}

	public VotingServerStandalone(String pathPK, String pathID, int listenPort, String bulletinBoardAddress, int bulletinBoardPort) {
		this(pathPK, pathID);
		System.out.println(String.format("Voting server started with parameters: path: %s, listenPort: %d, BBAddress: %s, BBPort: %d", pathPK, listenPort,
				bulletinBoardAddress, bulletinBoardPort));
		this.listenPort = listenPort;
		this.bulletinBoardAddress = bulletinBoardAddress;
		this.bulletinBoardPort = bulletinBoardPort;
	}

	private void init() {
		BufferedReader br;
		try {
			// Server expects a file containing all public keys of the clients
			// as a hex string, each line is expected to be one public key.
			// It also expects a file containing the IDs of the voters as Strings, one per line and
			// in the same order as the public keys.
			br = new BufferedReader(new FileReader(votersPublicKeysFile));
			int count = Integer.parseInt(br.readLine());
			Encryptor[] encryptors = new Encryptor[count];
			for (int i = 0; i < count; i++) {
				String tmp = br.readLine();
				System.out.println(String.format("Processing key %s", tmp));
				byte[] publicKey = Utilities.hexStringToByteArray(tmp); // converts the strings to bytes
				encryptors[i] = new Encryptor(publicKey); // and creates the server
			}
			br.close();
			
			br = new BufferedReader(new FileReader(votersIdsFile));
			count = Integer.parseInt(br.readLine());
			byte[][] voterIds = new byte[count][];
			for (int i = 0; i < count; i++) {
				String tmp = br.readLine();
				System.out.println(String.format("Processing id %s", tmp));
				byte[] id = Utilities.hexStringToByteArray(tmp);
				voterIds[i] = id;
			}
			br.close();
			
			if (voterIds.length != encryptors.length) throw new IllegalArgumentException("The length of voterID and publicKey File differ");			
			byte[] pubKey = Utilities.hexStringToByteArray(publicKey);
			byte[] privKey = Utilities.hexStringToByteArray(privateKey);
			
			// After all public keys have been read, create the core server
			serverCore = new VotingServerCore(new Decryptor(pubKey, privKey), voterIds, encryptors);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private int phase = -1;
	public void setPhase(int phase) {
		if (phase > this.phase) {
			this.phase = phase;
		} else {
			throw new IllegalStateException("Server cannot switch to a previous phase!");
		}
	}

	public void startServer() throws IOException {
		while (true) {
			switch (phase) {
			case PHASE_REGISTRATION: 	// only credential requests allowed
				acceptRegistration();
				break;
			case PHASE_COLLECT_BALLOT: 	// only ballot submission allowed
				acceptBallot();
				break;
			case PHASE_COUNT_AND_SUBMIT: // stops listening and publishes the result to the bulletin board
				return;
			}
		}
	}

	public void countAndPublish() {
		byte[] result = serverCore.getResult();
		byte[] out = new byte[result.length + 1];
		out[0] = PUBLISH_RESULT;
		for (int i = 0; i < result.length; i++)
			out[i + 1] = result[i];
		sendToBulletinBoard(out);
	}

	private void acceptBallot() {
		try {
			System.out.println("Waiting for ballot...");
			if (!Network.waitForClient(listenPort))
				return;
			byte[] input = Network.networkIn();
			System.out.println("Received request via network: " + Utilities.byteArrayToHexString(input));
			if (input[0] == SUBMIT_BALLOT) { // Ballot submitted
				byte[] ballot = new byte[input.length - 1];
				System.arraycopy(input, 1, ballot, 0, ballot.length); // cut of the request code
				serverCore.collectBallot(ballot); // ask server to decrypt and process the ballot
				Network.networkOut(new byte[] { ERROR_NO_ERROR });
				sendToBulletinBoard(input);
			} else { // anything else submitted
				Network.networkOut(new byte[] { ERROR_WRONG_PHASE });
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			Network.resetConnection();
		}
	}

	private void acceptRegistration() {
		try {
			System.out.println("Waiting for registration...");
			if (!Network.waitForClient(listenPort))
				return;
			byte[] input = Network.networkIn();
			System.out.println("Received request via network: " + Utilities.byteArrayToHexString(input));
			if (input[0] == REQUEST_CREDENTIAL) { // Registration
				byte[] voterID = new byte[input.length - 1];
				System.arraycopy(input, 1, voterID, 0, voterID.length);
				byte[] credential = serverCore.getCredential(voterID);
				byte[] out = new byte[credential.length + 1];
				out[0] = ERROR_NO_ERROR;
				for (int i = 0; i < credential.length; i++)
					out[i + 1] = credential[i];
				Network.networkOut(out);
			} else {
				Network.networkOut(new byte[] { ERROR_WRONG_PHASE });
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			Network.resetConnection();
		}
	}

	public static void main(String[] args) throws IOException {
		if (args.length < 2) {
			System.out.println("Parameter missing. Usage: VotingServerStandalone <path-to-pk-file> <path-to-id-file>");
			return;
		}
		VotingServerStandalone server;
		if (args.length >= 4) {
			// String pathPK, String pathID, int listenPort, String bulletinBoardAddress, int bulletinBoardPort
			server = new VotingServerStandalone(args[0], args[1], Integer.parseInt(args[2]), args[3], Integer.parseInt(args[4]));
		} else {
			// String pathPK, String pathID
			server = new VotingServerStandalone(args[0], args[1]);
		}
		VotingServerDialog window = new VotingServerDialog(server);
		window.start();
	}

	public void sendToBulletinBoard(byte[] data) {
		try {
			Network.connectToServer(bulletinBoardAddress, bulletinBoardPort);
			Network.networkOut(data);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			Network.resetConnection();
		}
	}

}
