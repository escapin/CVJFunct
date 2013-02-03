package de.uni.trier.infsec.protocols.smt_voting;


/*
 * Collection of agent identifiers.
 */
public class Identifiers {
	static final int SERVER_ID = -1;
	static final int BULLETIN_BOARD_ID = -2;
	static final int ADVERSARY_ID = -3; 
	// eligible voters get the identifiers in the range 0..Server.NumberOfVoters
	
	static final int DEFAULT_LISTEN_PORT_SERVER = 88; // Listen port for Voter requests
	static final int DEFAULT_LISTEN_PORT_BBOARD = 89; // Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_REQUEST = 90; // Listen port for result requests
	static final String DEFAULT_HOST_SERVER = "localhost";
	static final String DEFAULT_HOST_BBOARD = "localhost";
}
