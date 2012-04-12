package de.uni.trier.infsec.protocols.simplevoting;

import de.uni.trier.infsec.functionalities.pkenc.ideal.Decryptor;

// Because we do not have signatues yet, the server itself generates credentials .
//
// Class VotingServer should use this class (VotingServerCore) and glue it to the 
// networking. VotingServer should take messages from the network, 
// decide 
//
public class VotingServerCore {

	byte[][] votersPK;  // a collection of eligible voters' public keys
	Decryptor serverDecr; 
	
	/*
	 * The server is initialized with his decryptor and the list of (public keys of) 
	 * eligible voters.
	 */
	public VotingServerCore( byte[][] votersPK, Decryptor serverDecr ) {
		this.votersPK = votersPK;
		this.serverDecr = serverDecr;
	}
	
	/*
	 * Registration: the server generates a credential for a given voter ('voter' is 
	 * the public key of a voter), if it is not generated yet.
	 * The method returns an encrypted credential 
	 */
	public byte[] registration( byte[] voter ) {
		// - check whether voter is in the list votersPK
		// - check whether a credential for this voter has not been given yet
		// - if not, generate a new credential, store it somewhere, encrypt it and return
		// - if the credential was generated earlier, return it
		return null;
	}
	
	/*
	 * Takes a message 'ballot' checks its well-formedness and (if it is a valid ballot
	 * of a voter who has not voted yet) collects it
	 */
	public void collectBallot( byte[] ballot ) {
	}

	/*
	 * Formats the results of the election as a message and returns it.
	 */
	public byte[] getResult() {
		return null;
	}
	
}
