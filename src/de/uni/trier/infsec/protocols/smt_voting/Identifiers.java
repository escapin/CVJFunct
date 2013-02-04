package de.uni.trier.infsec.protocols.smt_voting;


/*
 * Collection of agent identifiers.
 */
public class Identifiers {
	static final int SERVER_ID = -1;
	static final int BULLETIN_BOARD_ID = -2;
	static final int ADVERSARY_ID = -3; 
	// eligible voters get the identifiers in the range 0..Server.NumberOfVoters
	
	public static final byte[] DOMAIN_SMT  = new byte[] {0x07, 0x08};
	public static final byte[] DOMAIN_AMT  = new byte[] {0x03, 0x04};
	public static final byte[] DOMAIN_NONE = new byte[] {0x00, 0x00};
	
	static final int DEFAULT_LISTEN_PORT_SERVER_AMT = 88; // Listen port for Voter requests
	static final int DEFAULT_LISTEN_PORT_SERVER_SMT = 89; // Listen port for Voter requests
	
	static final int DEFAULT_LISTEN_PORT_BBOARD_AMT = 90; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_SMT = 91; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_REQUEST = 92; 	// Listen port for result requests
	
	static final String DEFAULT_HOST_SERVER = "localhost";
	static final String DEFAULT_HOST_BBOARD = "localhost";
}
