package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.environment.Environment;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;


/*
 * A setup for a server and (multiple) honest clients using secure authenticated channel
 * (secure, authenticated message transmission functionality) to send their choices
 * to the server.
 *
 * The adversary determines two variants of voters'choices, one of which is picked, based
 * on the value of the secret bit. During the voting process the adversary determines actions
 * to be taken.
 */
public class HonestVotersSetup {

	static class Adversary {
		public final SMT.Channel channel_to_server;
		public final AMT.Channel channel_to_BB;

		public Adversary() throws SMTError, PKIError, NetworkError, AMTError {
			SMT.AgentProxy adversary_samt_proxy = SMT.register(Identifiers.ADVERSARY_ID);
			channel_to_server = adversary_samt_proxy.channelTo(Identifiers.SERVER_ID, "www.server.com", 89);
			AMT.AgentProxy adversary_amt_proxy = AMT.register(Identifiers.ADVERSARY_ID);
			channel_to_BB = adversary_amt_proxy.channelTo(Identifiers.BULLETIN_BOARD_ID, "www.bulletinboard.com", 89);
		}
	}

	/*
	 * Objects representing a result of the e-voting process. For now, two candidates only.
	 */
	static class Result {
		public int votesForA = 0;
		public int votesForB = 0;
	}

	/*
	 * Class with static fields to store the correct result computed from the votes actually
	 * used by the voters. This class plays the role of the class M from the hybrid approach,
	 * as described in the paper.
	 */
	static class CorrectResult {
		static public int votesForA = 0;
		static public int votesForB = 0;
	}


	static private boolean secret;  // SECRET INPUT

	static private Voter[] voters;
	static private Server server;
	static private BulletinBoard BB;


	/**
	 * Compute the correct result from a vector of voters' choices
	 */
	private static Result result(byte[] choices) {
		Result result = new Result();
		for( int i=0; i<choices.length; ++i ) {
			int candidate = choices[i];
			if (candidate==0) result.votesForA++;
			if (candidate==1) result.votesForB++;
			// all the remaining values as considered as invalid
		}
		return result;
	}

	/**
	 * Check whether two results are the same.
	 */
	private static boolean sameResults(Result res1, Result res2 ) {
		return res1.votesForA==res2.votesForA  &&  res1.votesForB==res2.votesForB;
	}


	/**
	 * Computes the correct result, as determined by the vectors voters' choices given as parameters,
	 * checks if these two vectors yield the same result. If not, false is returned. Otherwise, voters
	 * are registered and created.
	 */
	private static boolean select_voters_choices_and_create_voters(byte[] voterChoices1, byte[] voterChoices2) throws SMTError, PKIError, NetworkError {
		// we check whether voterChoices1 and voterChoices2 yield the same
		// results:
		boolean status = computeCorrectResult(voterChoices1, voterChoices2);
		if (!status) return false;

		// now, one of the vectors of voters' choices given by the adversary is chosen
		// to be used by the voters, depending on the value of the secret bit:
		byte[] voterChoices = chooseVoterChoices(voterChoices1, voterChoices2);

		// Register and create the voters
		registerAndCreateVoters(voterChoices);

		return true;
	}

	/**
	 * Checks whether voterChoices1 and voterChoices2 yield the same results
	 */
	private static boolean computeCorrectResult(byte[] voterChoices1, byte[] voterChoices2) {
		Result result1 = result(voterChoices1);
		Result result2 = result(voterChoices2);
		if( !sameResults(result1,result2) ) return false;
		CorrectResult.votesForA = result1.votesForA; // (hybrid approach extension)
		CorrectResult.votesForB = result1.votesForB; // (hybrid approach extension)
		return true;
	}

	/**
	 * One of the vectors of voters' choices given by the adversary is chosen
	 * to be used by the voters, depending on the value of the secret bit:
	 */
	private static byte[] chooseVoterChoices(byte[] voterChoices1, byte[] voterChoices2) {
		byte[] voterChoices = new byte[Server.NumberOfVoters];
		for (int i=0; i<Server.NumberOfVoters; ++i) {
			final byte data1 = voterChoices1[i];
			final byte data2 = voterChoices2[i];
			voterChoices[i] = (secret ? data1 : data2);
		}
		return voterChoices;
	}

	/**
	 * Register and create the voters.
	 */
	private static void registerAndCreateVoters(byte[] voterChoices) throws SMTError, PKIError, NetworkError {
		voters = new Voter[Server.NumberOfVoters];
                for( int i=0; i<Server.NumberOfVoters; ++i ) {
			SMT.AgentProxy voter_proxy = SMT.register(i);
			voters[i] = new Voter(voterChoices[i], voter_proxy);
		}
	}

	/**
	 * Register and create the server.
	 */
	private static void create_server() throws SMTError, PKIError, AMTError, NetworkError {
		SMT.AgentProxy server_samt_proxy = SMT.register(Identifiers.SERVER_ID);
		AMT.AgentProxy server_amt_proxy = AMT.register(Identifiers.SERVER_ID);
		server = new Server(server_samt_proxy, server_amt_proxy);
	}

	/**
	 * Register and create the bulletin board.
	 */
	private static void create_bulletin_board() throws AMTError, PKIError {
		// Register and create the bulletin board:
		AMT.AgentProxy BB_proxy = AMT.register(Identifiers.BULLETIN_BOARD_ID);
		BB = new BulletinBoard(BB_proxy);
	}

        private static void onVote() throws SMTError {
                int voter_id = Environment.untrustedInput();
                if (voter_id>=0 && voter_id<Server.NumberOfVoters) {
                        voters[voter_id].onSendBallot();
                }
        }

	/**
	 * Run the main loop of the setup.
	 *
	 * First, the adversary registers his SAMT and AMT functionalities. Then, in a loop, the
	 * adversary decides which actions are taken.
	 */
	private static void run() throws SMTError, PKIError, NetworkError, AMTError {
		Adversary adversary = new Adversary();
		// Main loop -- the adversary decides how many times it runs and what to do in each step:
		while( Environment.untrustedInput() != 0 )  {
			byte[] message;
			int decision = Environment.untrustedInput();
			switch (decision) {
			case 0:	// a voter (determined by the adversary) votes according to voterChoices
					onVote();
					break;

			case 1: // server reads a message (possibly a ballot) from a secure channel
					server.onCollectBallot();
					break;

			case 2: // the server sends the result of the election (if ready) over the network
					try {
						server.onSendResult("", 1);
					}
					catch (NetworkError err) {}
					break;

			case 3: // the server posts the result of the election (if ready) on the bulletin board
					server.onPostResult();
					break;

			case 4: // the bulletin board reads a message:
					BB.onPost();
					break;

			case 5: // the bulletin board sends its content (over the network):
					byte[] content = BB.onRequestContent();
					Environment.untrustedOutputMessage(content);
					break;

			case 6: // the adversary sends a message using its channel to the server
					message = Environment.untrustedInputMessage();
					adversary.channel_to_server.send(message);
					break;

			case 7: // the adversary sends a message using its channel to the bulletin board
					message = Environment.untrustedInputMessage();
					adversary.channel_to_BB.send(message);
					break;
			}
		}
	}

	public static void main(String[] args) throws SMTError, PKIError, NetworkError, AMTError {
		// the adversary determines two possible ways the voters vote:
		byte[] voterChoices1 = new byte[Server.NumberOfVoters];
		byte[] voterChoices2 = new byte[Server.NumberOfVoters];
		for( int i=0; i<Server.NumberOfVoters; ++i ) {
			voterChoices1[i] = (byte)Environment.untrustedInput();
			voterChoices2[i] = (byte)Environment.untrustedInput();
		}

		boolean status = select_voters_choices_and_create_voters(voterChoices1, voterChoices2);
		if (!status) return;
		create_server();
		create_bulletin_board();
		run();
	}
}
