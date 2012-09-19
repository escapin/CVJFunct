package de.uni.trier.infsec.protocols.simplevoting.voterGUI;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.FilenameFilter;
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
		cleanupFiles(path);
		File dir = new File(path);
		if (!dir.exists())
			dir.mkdirs();

		if (!path.endsWith(File.separator)) path = path + File.separator;
		File fPk = new File(path + "clientPK.evo");
		BufferedWriter bwPk = new BufferedWriter(new FileWriter(fPk));
		File fId = new File(path + "clientID.evo");
		BufferedWriter bwId = new BufferedWriter(new FileWriter(fId));
		
		bwPk.write(Integer.toString(count) + "\n");
		bwId.write(Integer.toString(count) + "\n");

		for (int i = 0; i < count; i++) {
			KeyPair kp = Encryption.generateKeyPair();

			String pubKey = Utilities.byteArrayToHexString(kp.publicKey);
			bwPk.write(pubKey + "\n");

			String name = String.format("voter%d", i);
			FileOutputStream f2pub = new FileOutputStream(path + name + ".pub");
			FileOutputStream f2priv = new FileOutputStream(path + name + ".pri");
			bwId.write(Utilities.byteArrayToHexString(name.getBytes()) + "\n");

			f2priv.write(kp.privateKey);
			f2priv.flush();
			f2priv.close();

			f2pub.write(kp.publicKey);
			f2pub.flush();
			f2pub.close();
		}
		bwPk.flush();
		bwPk.close();
		
		bwId.flush();
		bwId.close();
	}

	private static void cleanupFiles(String path) {
		File[] files = new File(path).listFiles(new FilenameFilter() {
			@Override
			public boolean accept(File arg0, String name) {
				return (name.endsWith("pri") || name.endsWith("pub") || name.equals("evo")); 
			}
		});
		for (File f : files) {
			f.delete();
		}
		File tmpdir = new File(System.getProperty("java.io.tmpdir") + File.separator + "evoting");
		try {			
			for (File f : tmpdir.listFiles()) f.delete();
			tmpdir.delete();
		} catch (Exception e) {}
	}

}
