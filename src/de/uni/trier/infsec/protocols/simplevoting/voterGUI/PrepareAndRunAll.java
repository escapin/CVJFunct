package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import de.uni.trier.infsec.protocols.simplevoting.NetworkProxy;

public class PrepareAndRunAll {
	
	public static void main(String[] args) throws IOException, InterruptedException {
		String cmd = "java";
		ProcessBuilder p1 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
				PrepareAndRunServer.class.getName());
		p1.redirectErrorStream(true);
		Process p1r = p1.start();
		BufferedReader br1 = new BufferedReader(new InputStreamReader(p1r.getInputStream()));
		
		ProcessBuilder p2 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
				PrepareAndRunClient.class.getName());
		p2.redirectErrorStream(true);
		Process p2r = p2.start();
		BufferedReader br2 = new BufferedReader(new InputStreamReader(p2r.getInputStream()));
		
		ProcessBuilder p3 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
				BulletinBoardDialog.class.getName());
		p3.redirectErrorStream(true);
		Process p3r = p3.start();
		BufferedReader br3 = new BufferedReader(new InputStreamReader(p3r.getInputStream()));
		
		ProcessBuilder p4 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
				NetworkProxy.class.getName());
		p4.redirectErrorStream(true);
		Process p4r = p4.start();
		BufferedReader br4 = new BufferedReader(new InputStreamReader(p4r.getInputStream()));
		
		while (true) {
			while (br1.ready()) System.out.println("<Server> " + br1.readLine());
			while (br2.ready()) System.out.println("<Clients> " + br2.readLine());
			while (br3.ready()) System.out.println("<BulletinBoard> " + br3.readLine());
			while (br4.ready()) System.out.println("<NetworkProxy> " + br4.readLine());
			Thread.sleep(500);
		}
		
	}
}
