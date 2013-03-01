package de.uni.trier.infsec.tests;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.ProcessBuilder.Redirect;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.lib.network.NetworkError;

public class TestSMTVoting extends TestCase {

	public static final String PATH = System.getProperty("java.io.tmpdir") + "/smtvote_log/";
	
	@Test
	public void testRealPKIRemote() throws PKIError, NetworkError, Exception {
		Process pr1 = null;
		Process pr21 = null;
		Process pr22 = null;
		Process pr31 = null;
		Process pr32 = null;
		try {
			String cmd = "java";
			File f = new File(PATH);
			f.mkdirs();
			
			ProcessBuilder p1 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.functionalities.pki.real.PKIServer");
			ProcessBuilder p21 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.ServerRegisterStandalone");
			ProcessBuilder p22 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.ServerStandalone");
			ProcessBuilder p31 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRegisterStandalone");
			ProcessBuilder p32 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.BulletinBoardStandalone");
			ProcessBuilder p6 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.BulletinBoardRequestTool");

			System.out.println("Starting PKIServer");
			p1.redirectError(Redirect.appendTo(new File(PATH + "pkiserver.log")));
			p1.redirectOutput(Redirect.appendTo(new File(PATH + "pkiserver.log")));
			pr1 = p1.start();
			Thread.sleep(5000);

			System.out.println("Starting ServerStandalone");
			p21.redirectError(Redirect.appendTo(new File(PATH + "server.log")));
			p21.redirectOutput(Redirect.appendTo(new File(PATH + "server.log")));
			pr21 = p21.start();
			
			Thread.sleep(5000);
			p22.redirectError(Redirect.appendTo(new File(PATH + "server.log")));
			p22.redirectOutput(Redirect.appendTo(new File(PATH + "server.log")));
			pr22 = p22.start();
			Thread.sleep(5000);
			
			System.out.println("Starting BulletinBoardStandalone");
			p31.redirectOutput(Redirect.appendTo(new File(PATH + "BB.log")));
			p31.redirectError(Redirect.appendTo(new File(PATH + "BB.log")));
			pr31 = p31.start();
			Thread.sleep(5000);

			p32.redirectOutput(Redirect.appendTo(new File(PATH + "BB.log")));
			p32.redirectError(Redirect.appendTo(new File(PATH + "BB.log")));
			pr32 = p32.start();
			Thread.sleep(5000);

			for (int i = 0; i < 50; i++) {				
				ProcessBuilder p4 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.VoterRegisterStandalone", "" + i);
				p4.redirectError(Redirect.appendTo(new File(PATH + "voter" + i + ".log")));
				p4.redirectOutput(Redirect.appendTo(new File(PATH + "voter" + i + ".log")));
				p4.start();
				Thread.sleep(2000);
				System.out.println(i + " registered.");
			}
			
			for (int i = 0; i < 50; i++) {				
				ProcessBuilder p5 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.VoterVoteStandalone", String.format("%02d", i % 2), Integer.toString(i));
				p5.redirectError(Redirect.appendTo(new File(PATH + "votervote" + i + ".log")));
				p5.redirectOutput(Redirect.appendTo(new File(PATH + "votervote" + i + ".log")));
				p5.start();
				Thread.sleep(2000);
				System.out.println(i + " did his vote.");
			}

			Thread.sleep(2000);
			p6.redirectError(Redirect.appendTo(new File(PATH + "BB_REQ.log")));
			p6.redirectOutput(Redirect.appendTo(new File(PATH + "BB_REQ.log")));
			p6.start();
			Thread.sleep(10000);
			
			// String bb = readFileAsString(PATH + "BB.log"); // Received Message: 
			String server = readFileAsString(PATH + "server.log"); // Server successfully collected all votes. Terminating.
			
			assertTrue("Server did not terminate correctly!", server.contains("Server successfully collected all votes. Terminating."));
		} finally {
			if (pr1 != null) pr1.destroy();
			if (pr21 != null) pr21.destroy();
			if (pr22 != null) pr22.destroy();
			if (pr31 != null) pr31.destroy();
			if (pr32 != null) pr32.destroy();
		}
	}

	private String readFileAsString(String path) throws Exception {
		File f = new File(path);
		assertTrue("File " + path + "does not exist", f.exists());
		BufferedReader br = new BufferedReader(new FileReader(f));
		String s = null;
		StringBuffer sb = new StringBuffer();
		while ((s = br.readLine()) != null) {
			sb.append(s);
		}
		br.close();
		return sb.toString();
	}

	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
		
		File dir = new File(PATH);
		if (dir.exists()) {			
			for (File ff :  dir.listFiles())
				ff.delete();
		}
	}

}
