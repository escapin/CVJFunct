package de.uni.trier.infsec.protocols.smt_voting;

public class Parameters {
	static final int DEFAULT_LISTEN_PORT_SERVER_AMT = 4088; // Listen port for Voter requests
	static final int DEFAULT_LISTEN_PORT_SERVER_SMT = 4089; // Listen port for Voter requests

	static final int DEFAULT_LISTEN_PORT_BBOARD_AMT = 4090; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_SMT = 4091; 		// Listen port for Server requests
	static final int DEFAULT_LISTEN_PORT_BBOARD_REQUEST = 4092; 	// Listen port for result requests

	static final String DEFAULT_HOST_SERVER = "localhost";
	static final String DEFAULT_HOST_BBOARD = "localhost";
}
