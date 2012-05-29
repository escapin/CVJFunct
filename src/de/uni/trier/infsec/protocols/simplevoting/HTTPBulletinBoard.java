package de.uni.trier.infsec.protocols.simplevoting;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import de.uni.trier.infsec.lib.network.Network;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

public class HTTPBulletinBoard {

	public HTTPBulletinBoard(int httpPort) throws IOException {
		super();
		initialize(httpPort);
	}

	public static void main(String[] args) throws IOException {
		int listenPort = DEFAULT_BULLETIN_BOARD_PORT;
		int httpPort = 8888;
		if (args.length >= 2) {
			listenPort = Integer.parseInt(args[0]);
			httpPort   = Integer.parseInt(args[1]);
		}
		HTTPBulletinBoard bulletinBoard = new HTTPBulletinBoard(httpPort);
		bulletinBoard.start(listenPort);
		System.out.println(String.format("Bulletin Board HTTP Server is listening to port %d. Webserver is running on port %d", listenPort, httpPort));
	}

	private ArrayList<byte[]> data = new ArrayList<byte[]>();
	public static final int DEFAULT_BULLETIN_BOARD_PORT = 4554;
	
	private void initialize(int httpPort) throws IOException {

		InetSocketAddress addr = new InetSocketAddress(httpPort);
		HttpServer server = HttpServer.create(addr, 0);

		server.createContext("/", new BulletinBoardHandler());
		server.setExecutor(Executors.newCachedThreadPool());
		server.start();
	}

	private void start(int port) {
		while (true) {
			try {
				Network.waitForClient(port);
				byte[] in = Network.networkIn();
				if (in != null) data.add(in);
			} catch (Exception e) {
			}
		}
	}
	
	public static final String htmlTemplate = "<html><body><center><h1>eVoting - Bulletin board</h1></center><h2>Casted Votes:</h2><table border='1' style='border-collapse:collapse'>%s</table><h2>Election Results:</h2><table border='1' style='border-collapse:collapse'>%s</table></body></html>";
	public static final String tableRow = "<tr><td>%s</td></tr>";
	public static final String resultLine = "<tr><td>Choice %x has %d votes.</td></tr>";
	
	
	class BulletinBoardHandler implements HttpHandler {
		public void handle(HttpExchange exchange) throws IOException {
			try {
				
				String requestMethod = exchange.getRequestMethod();
				if (requestMethod.equalsIgnoreCase("GET")) {
					Headers responseHeaders = exchange.getResponseHeaders();
					responseHeaders.set("Content-Type", "text/html");
					exchange.sendResponseHeaders(200, 0);
					OutputStream responseBody = exchange.getResponseBody();
					String ballots = "";
					String results = "";
					for (byte[] dataItem : data) {
						if (dataItem[0] == VotingServerStandalone.PUBLISH_RESULT) {
							int i = 1;
							while (i < dataItem.length - 1) {
								byte choice = dataItem[i++];
								byte[] bcount = new byte[4];
								for (int j = 0; j < 4; j++) bcount[j] = dataItem[i++];
								int count = MessageTools.byteArrayToInt(bcount);
								results += String.format(resultLine, choice, count);
							}
						}
						if (dataItem[0] == VotingServerStandalone.SUBMIT_BALLOT) {
							ballots += String.format(tableRow, Utilities.byteArrayToHexString(dataItem));
						}
					}
					String html = String.format(htmlTemplate, ballots, results);
					responseBody.write(html.getBytes());
					responseBody.flush();
					responseBody.close();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

}
