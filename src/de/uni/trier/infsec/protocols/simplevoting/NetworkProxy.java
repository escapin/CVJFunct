package de.uni.trier.infsec.protocols.simplevoting;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

import de.uni.trier.infsec.environment.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class NetworkProxy {

	public static final int DEFAULT_PROXY_PORT = 4949;
	private int serverPort;
	private String serverAddress;
	
	public NetworkProxy(int listenPort, String serverAddress, int serverPort) throws IOException {
		this.serverSocket = new ServerSocket(listenPort);
		this.serverPort = serverPort;
	}

	private class NetworkThread implements Runnable {
		private Socket connection;
		public NetworkThread(Socket s) {
			this.connection = s;
			
		}
		@Override
		public void run() {
			byte[] buffer = null;
			try {
				connection.setSoTimeout(30000);
				int length = connection.getInputStream().read();
				buffer = new byte[length];
				connection.getInputStream().read(buffer);
				System.out.println("Forwarding to Server: " + Utilities.byteArrayToHexString(buffer));
				
				byte[] response = handleConnection(buffer);
				
				if (response != null) {
					System.out.println("Forwarding to Client: " + Utilities.byteArrayToHexString(response));
					connection.getOutputStream().write(response.length);
					connection.getOutputStream().write(response);
					connection.getOutputStream().flush();
				}
			} catch (IOException e) {
			} finally {
				try {
					connection.close();
				} catch (IOException e) {
				}
			}
		}
	}

	public synchronized byte[] handleConnection(byte[] data) {
		byte[] response = null;
		try {
			Network.connectToServer(serverAddress, serverPort);
			Network.networkOut(data);
			response = Network.networkIn();
		} catch (NetworkError e) {
		} finally {
			Network.resetConnection();
		}
		return response;
	}

	ServerSocket serverSocket = null;
	public void waitForClients() {
		try {
			while (true) {
				try {
					Socket s = serverSocket.accept();
					System.out.println("Received connection. Starting NetworkThread");
					Thread t = new Thread(new NetworkThread(s));
					t.start();
				} catch (Exception e) {
					System.out.println("Exception occured: " + e.getMessage());
				}
			}
		} finally {
			if (serverSocket != null) {
				try {
					serverSocket.close();
				} catch (IOException e) { }
				serverSocket = null;
			}
		}
	}
	
	public static void main(String[] args) throws IOException {
		int listenPort = DEFAULT_PROXY_PORT;
		int serverPort = Network.DEFAULT_PORT;
		String serverAddress = Network.DEFAULT_SERVER;
		if (args.length >= 3) {
			listenPort = Integer.parseInt(args[0]);
			serverAddress = args[1];
			serverPort = Integer.parseInt(args[2]);
		}
		
		NetworkProxy proxy = new NetworkProxy(listenPort, serverAddress, serverPort);
		proxy.waitForClients();
	}

}
