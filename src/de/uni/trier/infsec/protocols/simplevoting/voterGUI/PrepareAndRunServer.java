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
	public static final String TEMP_PATH = System.getProperty("java.io.tmpdir")
			+ "/evoting/";
	private static String dirPath = TEMP_PATH;
	private static int voterCount = VOTER_COUNT;

	public static void main(String[] args) throws IOException {
		if (args.length >= 2) {
			try {
				if ((new File(args[0])).isDirectory()) {
					dirPath = args[0];
				}
			} catch (Exception e) {
			}
			try {
				if (Integer.parseInt(args[1]) > 0) {
					voterCount = Integer.parseInt(args[1]);
				}
			} catch (Exception e) {
			}
		}
		prepareFiles(dirPath, voterCount);
		System.out.println("Preparation for server finished. Starting Server.");
		VotingServerStandalone.main(new String[] { dirPath + File.separator + "clients.evo" });
	}

	public static void prepareFiles(String path, int count) throws IOException {
		File dir = new File(path);
		if (!dir.exists())
			dir.mkdirs();

		if (!path.endsWith(File.separator)) path = path + File.separator;
		File f = new File(path + "clients.evo");
		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
		bw.write(Integer.toString(count) + "\n");

		for (int i = 0; i < count; i++) {
			KeyPair kp = Encryption.generateKeyPair();

			String pubKey = Utilities.byteArrayToHexString(kp.publicKey);
			bw.write(pubKey + "\n");

			String name = String.format("voter%d", i);
			FileOutputStream f2pub = new FileOutputStream(path + name + ".pub");
			FileOutputStream f2priv = new FileOutputStream(path + name + ".pri");

			f2priv.write(kp.privateKey);
			f2priv.flush();
			f2priv.close();

			f2pub.write(kp.publicKey);
			f2pub.flush();
			f2pub.close();
		}
		bw.flush();
		bw.close();
	}

}
