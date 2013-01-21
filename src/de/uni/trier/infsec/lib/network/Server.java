package de.uni.trier.infsec.lib.network;

public class Server {

	/**
	 * Returns the next requests (a message).
	 */
	byte[] nextRequest() throws NetworkError {
		return null;
		// TODO
	}

	/**
	 * Sends a response (a message) to the last request (that is the client who
	 * sent the last request obtained by calling method 'nextRequest').
	 */
	void response(byte[] message) throws NetworkError {
		// TODO
	}
	// I can imagine that we could have a single-threaded implementation of this class, but
	// that could be awkward. Probably it would be better to have multi-threaded implementation,
	// with separate threads for accepting client connections and for waiting for messages and
	// putting those messages along with the sockets in some queue, from which method 'response'
	// would take requests. In any case, however, we assume that methods 'nextRequest' and 'response'
	// are always called from one (main) thread (so the notion of 'the last request' makes sense).
}
