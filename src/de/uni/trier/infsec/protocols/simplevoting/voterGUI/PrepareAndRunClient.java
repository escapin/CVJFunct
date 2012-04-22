package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.io.IOException;

import de.uni.trier.infsec.protocols.simplevoting.VoterStandalone;

public class PrepareAndRunClient {

	public static void main(String[] args) throws IOException {

		if (args.length < 1) {
			for (int i = 0; i < PrepareAndRunServer.VOTER_COUNT; i++) {
				String voter = PrepareAndRunServer.TEMP_PATH;
				voter += "voter" + i;
				String cmd = "java";
				ProcessBuilder p = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null),
						"de.uni.trier.infsec.protocols.simplevoting.VoterStandalone", voter + ".pub", voter + ".pri");
				p.start();
			}
		} else {
			String voter = PrepareAndRunServer.TEMP_PATH;
			voter += "voter" + args[0];
			VoterStandalone.main(new String[] { voter + ".pub", voter + ".pri" });
		}
	}
}
