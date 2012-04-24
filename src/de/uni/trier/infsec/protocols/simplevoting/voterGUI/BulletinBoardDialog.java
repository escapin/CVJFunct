package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.awt.BorderLayout;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.concurrent.Executors;

import javax.swing.JFrame;
import javax.swing.JTextPane;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import de.uni.trier.infsec.lib.network.Network;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerStandalone;
import de.uni.trier.infsec.utils.Utilities;

public class BulletinBoardDialog {

	public static void main(String[] args) throws IOException {
		BulletinBoardDialog window = new BulletinBoardDialog();
		window.initialize();
		window.work();
		// window.show();
		
	}

	private JTextPane textPane;
	private JFrame frmEvotingBulletinBoard;
	private ArrayList<byte[]> data = new ArrayList<byte[]>();
	public static final int DEFAULT_BULLETIN_BOARD_PORT = 5656;
	

	private void initialize() throws IOException {
		frmEvotingBulletinBoard = new JFrame();
		frmEvotingBulletinBoard.setTitle("eVoting Bulletin Board");
		frmEvotingBulletinBoard.setBounds(100, 100, 759, 439);
		frmEvotingBulletinBoard.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

		textPane = new JTextPane();
		textPane.setEditable(false);
		frmEvotingBulletinBoard.getContentPane().add(textPane, BorderLayout.CENTER);

		InetSocketAddress addr = new InetSocketAddress(8000);
		HttpServer server = HttpServer.create(addr, 0);

		server.createContext("/", new MyHandler());
		server.setExecutor(Executors.newCachedThreadPool());
		server.start();
		System.out.println(String.format("Bulletin Board HTTP Server is listening to port %d. Webserver is running on port %d", DEFAULT_BULLETIN_BOARD_PORT, 8000));
	}

	private void work() {
		while (true) {
			try {
				Network.waitForClient(DEFAULT_BULLETIN_BOARD_PORT);
				byte[] in = Network.networkIn();
				textPane.setText(textPane.getText() + Utilities.byteArrayToHexString(in) + "\n");
				data.add(in);
			} catch (Exception e) {
			}
		}
	}
	
	public void show() {
		frmEvotingBulletinBoard.setVisible(true);
	}

	class MyHandler implements HttpHandler {
		public void handle(HttpExchange exchange) throws IOException {
			String requestMethod = exchange.getRequestMethod();
			if (requestMethod.equalsIgnoreCase("GET")) {
				Headers responseHeaders = exchange.getResponseHeaders();
				responseHeaders.set("Content-Type", "text/plain");
				exchange.sendResponseHeaders(200, 0);

				OutputStream responseBody = exchange.getResponseBody();
				responseBody.write("eVoting: Bulletin board\n\n".getBytes());
				for (byte[] dataItem : data) {
					if (dataItem[0] == VotingServerStandalone.PUBLISH_RESULT) responseBody.write("RESULT: ".getBytes());
					if (dataItem[0] == VotingServerStandalone.SUBMIT_BALLOT) responseBody.write("BALLOT: ".getBytes());
					responseBody.write((Utilities.byteArrayToHexString(dataItem) + "\n\n").getBytes());
				}
				responseBody.close();
			}
		}
	}

}
