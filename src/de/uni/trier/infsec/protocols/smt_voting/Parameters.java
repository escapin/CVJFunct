package de.uni.trier.infsec.protocols.smt_voting;

public class Parameters {
	static final int DEFAULT_LISTEN_PORT_SERVER_AMT = 88; // Listen port for Voter requests
	static final int DEFAULT_LISTEN_PORT_SERVER_SMT = 89; // Listen port for Voter requests

	static final int DEFAULT_LISTEN_PORT_BBOARD_AMT = 90; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_SMT = 91; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_REQUEST = 92; 	// Listen port for result requests

	static final String DEFAULT_HOST_SERVER = "localhost";
	static final String DEFAULT_HOST_BBOARD = "localhost";
}
