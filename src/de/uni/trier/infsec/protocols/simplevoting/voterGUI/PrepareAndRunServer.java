package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;

import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.lib.crypto.Encryption;
import de.uni.trier.infsec.protocols.simplevoting.VotingServerStandalone;
import de.uni.trier.infsec.utils.Utilities;

public class PrepareAndRunServer {
	
	public static final int VOTER_COUNT = 5;
	public static final String TEMP_PATH = System.getProperty("java.io.tmpdir") + "/evoting/";
	
	public static void main(String[] args) throws IOException {
		File dir = new File(TEMP_PATH);
		if (!dir.exists()) dir.mkdirs();
		
		File f = new File(TEMP_PATH + "clients.evo");
		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
		bw.write(Integer.toString(VOTER_COUNT) + "\n");

		for (int i = 0; i < VOTER_COUNT; i++) {
			KeyPair kp = Encryption.generateKeyPair();
			
			String pubKey = Utilities.byteArrayToHexString(kp.publicKey);
			String privKey = Utilities.byteArrayToHexString(kp.privateKey);
			bw.write(pubKey + "\n");
			
			String name = String.format("voter%d", i);
			FileOutputStream f2pub = new FileOutputStream(TEMP_PATH + name + ".pub");
			FileOutputStream f2priv = new FileOutputStream(TEMP_PATH + name + ".pri");

			f2priv.write(kp.privateKey);
			f2priv.flush();
			f2priv.close();

			f2pub.write(kp.publicKey);
			f2pub.flush();
			f2pub.close();
			
			System.out.println("pub");
			System.out.println(pubKey);
			System.out.println("priv");
			System.out.println(privKey);
		}
		bw.flush();
		bw.close();
		
		VotingServerStandalone.main(new String[] {f.getAbsolutePath()});
	}

}
