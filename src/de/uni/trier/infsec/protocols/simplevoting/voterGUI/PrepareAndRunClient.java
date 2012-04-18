package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import de.uni.trier.infsec.protocols.simplevoting.VoterStandalone;

public class PrepareAndRunClient {

	
	public static void main(String[] args) {
		
		String voter = PrepareAndRunServer.TEMP_PATH; 
		if (args.length < 1) {
			voter += "voter" + (int) (Math.random() * PrepareAndRunServer.VOTER_COUNT);
		} else {
			voter += "voter" + args[0];
		}
		
		VoterStandalone.main(new String[] {voter + ".pub", voter + ".priv"});
		
	}
}
