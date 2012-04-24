package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;

import de.uni.trier.infsec.protocols.simplevoting.VoterStandalone;

public class PrepareAndRunClient {
	
	private static ArrayList<BufferedReader> outputReader = new ArrayList<BufferedReader>();

	public static void main(String[] args) throws IOException, InterruptedException {
		if (args.length < 1) {
			for (int i = 0; i < PrepareAndRunServer.VOTER_COUNT; i++) {
				String voter = PrepareAndRunServer.TEMP_PATH;
				voter += "voter" + i;
				String cmd = "java";
				ProcessBuilder p = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
						"de.uni.trier.infsec.protocols.simplevoting.VoterStandalone", voter + ".pub", voter + ".pri");
				p.redirectErrorStream(true);
				Process pr = p.start();
				outputReader.add(new BufferedReader(new InputStreamReader(pr.getInputStream())));
			}
		} else {
			String voter = PrepareAndRunServer.TEMP_PATH;
			voter += "voter" + args[0];
			VoterStandalone.main(new String[] { voter + ".pub", voter + ".pri" });
		}
		
		while (true) {
			for (BufferedReader br : outputReader) {
				while (br.ready()) System.out.println(br.readLine());
			}
			Thread.sleep(1000);
		}
	}
}
