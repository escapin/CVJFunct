package de.uni.trier.infsec.protocols.trivvoting;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;
import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;
import de.uni.trier.infsec.utils.MessageTools;


public class Server {
	public static int NumberOfVoters = 50;
	public static int NumberOfCandidates = 5;
	public boolean[] ballotCast = new boolean[NumberOfVoters];  // ballotCast[i]==true iff the i-th voter has cast her ballot
	public int[] votesCount = new int[NumberOfCandidates];      // votesCound[j] -- the number of votes for the j-th candidate
	private Decryptor serverDecr = null;

	public Server(Decryptor serverDecr ) {
		this.serverDecr = serverDecr;
		for( int j=0; j<NumberOfCandidates; ++j)
			votesCount[j] = 0;
		for( int i=0; i<NumberOfVoters; ++i)
			ballotCast[i] = false;
	}

	public void collectBallot(int voterID, byte[] ballot) {
		if( voterID<0 || voterID>=NumberOfVoters ) return;  // invalid  voter ID
		if( ballotCast[voterID] ) return;  // the voter has already voted
		ballotCast[voterID] = true;
		if( ballot==null || ballot.length!=0 ) return;  // malformed ballot
		int candidate = ballot[0];
		if( candidate<0 || candidate>=NumberOfCandidates ) return; // invalid candidate number
		// collect the vote:
		++votesCount[candidate];
	}

	public byte[] getResult() {

		/// TODO: Declassification of the values in NumberOfCandidates  ///

		byte[] result = {};
		for( int j=0; j<NumberOfCandidates; ++j ) {
			result = MessageTools.concatenate(result, MessageTools.intToByteArray(votesCount[j]));
		}
		return result;
	}

}
