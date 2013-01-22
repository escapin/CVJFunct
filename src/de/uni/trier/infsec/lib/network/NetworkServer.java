package de.uni.trier.infsec.lib.network;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Hashtable;

import de.uni.trier.infsec.utils.Utilities;


public class NetworkServer {
	
	// I can imagine that we could have a single-threaded implementation of this class, but
	// that could be awkward. Probably it would be better to have multi-threaded implementation,
	// with separate threads for accepting client connections and for waiting for messages and
	// putting those messages along with the sockets in some queue, from which method 'response'
	// would take requests. In any case, however, we assume that methods 'nextRequest' and 'response'
	// are always called from one (main) thread (so the notion of 'the last request' makes sense).
	
	// --> Now we have one Thread listening for connections and one Thread for each connection (reading the message).
	// The Messages get cached within a queue and every call to nextRequest returns the next element.
	
	private static final int LISTEN_PORT = 7070; // Default listening port. After connection is established, there will be another port used for communication!
	private static Hashtable<Socket, byte[]> queue = new Hashtable<>(); // Not HashMap because Hashtable is Thread-safe!
	private static Socket current = null; // Socket of the current message. Needed to answere the last request which has been processed
	
	static Thread listenThread = null; // Thread which is listening for new connections
	
	/**
	 * Returns the next requests (a message).
	 */
	public static byte[] nextRequest() throws NetworkError {
		if (listenThread == null) { // TODO: Start server manually or like this (within first call of "nextRequest"?
			Runnable listenRunnable = new ListenThread();
			listenThread = new Thread(listenRunnable);
			listenThread.start();
		}
		
		if (queue.keys().hasMoreElements()) {
			current = queue.keys().nextElement();
			byte[] msg = queue.get(current);
			queue.remove(current); // Removed from queue straight after it has been processed. Avoids illegal messages to stay in queue forever!
			return msg;
		}
		return null;
	}

	/**
	 * Sends a response (a message) to the last request (that is the client who
	 * sent the last request obtained by calling method 'nextRequest').
	 */
	public static void response(byte[] message) throws NetworkError {
		OutputStream os;
		try {
			os = current.getOutputStream();
			os.write(message);
			os.flush();
			os.close();
			
			current.close();
			current = null;
		} catch (IOException e) {
			e.printStackTrace();
			throw new NetworkError();
		}
	}

	
	/**
	 * Returns the next request (a message) and responds right away with the emtpy response.
	 */
	public static byte[] read() throws NetworkError {
		byte[] message = nextRequest();
		response(null);
		return message;
	}
	
	
	///// Implementation //////
	
	private static void readMessageInThread(Socket socket) {
		ReaderThread rt = new ReaderThread(socket);
		Thread t = new Thread(rt);
		t.start();
	}
	
	static class ReaderThread implements Runnable {
		Socket mysock = null;
		public ReaderThread(Socket s) {
			mysock = s;
		}
		
		@Override
		public void run() {
			try {
				InputStream is = mysock.getInputStream();
				ByteArrayOutputStream buffer = new ByteArrayOutputStream(); // we can handle Messages up to 1K
				byte[] bufferArr = new byte[512];
				while (is.available() > 0) buffer.write(bufferArr, 0, is.read(bufferArr));
				queue.put(mysock, buffer.toByteArray()); // Put the received message to the queue. Socket is kept open!
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	};
	
	static class ListenThread implements Runnable {
		private ServerSocket server = null;
		@Override
		public void run() {
			// If not already done: Init server
			if (server == null) {
				try {
					server = new ServerSocket(LISTEN_PORT);
				} catch (IOException e) {
					e.printStackTrace();
					return;
				}
			}
			
			try {
				while (true) {					
					Socket next = server.accept();
					readMessageInThread(next);
				}
			} catch (IOException e) {
				e.printStackTrace();
				return;
			}			
		}
	};
	
	public static void main(String[] args) throws NetworkError {
		while (true) {
			byte[] b = nextRequest();
			if (b != null ) {
				System.out.println(Utilities.byteArrayToHexString(nextRequest()));
				response(new byte[] {0x66, 0x33});
				break;
			}
		}
	}
	
}
