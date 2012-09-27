package de.uni.trier.infsec.protocols.trivvoting;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Encryptor;

/*
 * Voter client for TivVoting.
 */
public class Voter {
	private Encryptor serverEnc = null;

	public Voter(Encryptor serverEnc) {
		this.serverEnc = serverEnc;
	}

	public byte[] makeBallot(byte vote) {
		byte [] myVote = new byte[] {vote};
		byte [] ballot = myVote;
		return ballot;
	}
}
