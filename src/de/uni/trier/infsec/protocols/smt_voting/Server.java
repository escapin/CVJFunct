package de.uni.trier.infsec.protocols.smt_voting;

import de.uni.trier.infsec.functionalities.amt.real.AMT;
import de.uni.trier.infsec.functionalities.amt.real.AMT.AMTError;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.functionalities.smt.real.SMT.SMTError;
import de.uni.trier.infsec.lib.network.NetworkClient;
import de.uni.trier.infsec.lib.network.NetworkError;

/*
 * The server of TrivVoting. Collects votes send to it directly (via method call).
 * 
 * Two-candidates case only (for now).
 */
public class Server {

	public static final int NumberOfVoters = 50;
	private final boolean[] ballotCast;  // ballotCast[i]==true iff the i-th voter has already cast her ballot
	private int votesForA;
	private int votesForB;
	private final SMT.AgentProxy samt_proxy;
	private final AMT.Channel channel_to_BB;

	public Server(SMT.AgentProxy samt_proxy, AMT.AgentProxy amt_proxy) throws AMTError, PKIError, NetworkError {
		votesForA = 0;
                votesForB = 0;
                this.samt_proxy = samt_proxy;
		channel_to_BB = amt_proxy.channelTo(Identifiers.BULLETIN_BOARD_ID, Parameters.DEFAULT_HOST_BBOARD, Parameters.DEFAULT_LISTEN_PORT_BBOARD_AMT);
                ballotCast = new boolean[NumberOfVoters]; // initially no voter has cast her ballot
	}

	/*
	 * Collect one ballot (read from a secure channel)
	 */
	public void onCollectBallot() throws SMTError {
		SMT.AuthenticatedMessage am = samt_proxy.getMessage(Parameters.DEFAULT_LISTEN_PORT_SERVER_SMT);
		if (am==null) return;
		int voterID = am.sender_id;
		byte[] ballot = am.message;

		if( voterID<0 || voterID>=NumberOfVoters ) return;  // invalid  voter ID
		if( ballotCast[voterID] ) return;  // the voter has already voted
		ballotCast[voterID] = true; 
		if( ballot==null || ballot.length!=1 ) return;  // malformed ballot
		int candidate = ballot[0];
		if (candidate==0) ++votesForA;
		if (candidate==1) ++votesForB;
		// all the remaining values are consider invalid
	}

	/*
	 * Returns true if the result is ready, that is if all the eligible voters have already voted.
	 */
	public boolean resultReady() {
		for( int i=0; i<NumberOfVoters; ++i ) {
			if( !ballotCast[i] )
				return false;
		}
		return true;
	}

	/*
	 * Send the result (if ready) of the election over the network.
	 */
	public void onSendResult(String addr, int port) throws NetworkError {
		byte[] result = getResult();
		if (result != null)
			NetworkClient.send(result, addr, port);
	}

	/*
	 * Post the result (if ready) on the bulletin board.
	 */
	public void onPostResult() throws AMTError {
		byte[] result = getResult();
		if (result != null)
			channel_to_BB.send(result);
	}

	private byte[] getResult() {
		if (!resultReady()) return null; // the result is only returned when all the voters have voted

		// PROVE THAT
		// 		votesForA == HonestVotersSetup.CorrectResult.votesForA
		// 		votesForB == HonestVotersSetup.CorrectResult.votesForB
		// (this shows that the extension is conservative)
		votesForA = HonestVotersSetup.CorrectResult.votesForA; // (hybrid approach extension)
		votesForB = HonestVotersSetup.CorrectResult.votesForB; // (hybrid approach extension)

		return formatResult(votesForA, votesForB);
	}

	/*
	 * Format the result of the election.
	 */
	private static byte[] formatResult(int a, int b) {
		String s = "Result of the election:";
		s += "  Number of voters = " + NumberOfVoters + "\n";
		s += "  Number of votes for candidate 1 =" + a + "\n";
		s += "  Number of votes for candidate 2 =" + b + "\n";
		return s.getBytes();
	}
}
