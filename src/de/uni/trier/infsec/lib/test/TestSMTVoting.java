package de.uni.trier.infsec.lib.test;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.lib.network.NetworkError;

public class TestSMTVoting extends TestCase {

	@Test
	public void testRealPKIRemote() throws PKIError, NetworkError, Exception {
		Process pr1 = null;
		Process pr2 = null;
		Process pr3 = null;
		try {
			String cmd = "java";
			ProcessBuilder p1 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.functionalities.pki.real.PKIServer");
			ProcessBuilder p2 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.ServerStandalone");
			ProcessBuilder p3 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.BulletinBoardStandalone");
//			p1.redirectErrorStream(true);
//			p1.redirectOutput(Redirect.INHERIT);
//			pr1 = p1.start();
//			Thread.sleep(1000);
//			
//			p2.redirectErrorStream(true);
//			p2.redirectOutput(Redirect.INHERIT);
//			pr2 = p2.start();
//			Thread.sleep(1000);
			
//			p3.redirectErrorStream(true);
//			p3.redirectOutput(Redirect.INHERIT);
//			pr3 = p3.start();
//			Thread.sleep(1000);
//			
			for (int i = 0; i < 50; i++) {				
				ProcessBuilder p4 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.VoterStandalone", Integer.toString(i % 2), Integer.toString(i));
				p4.start();
				p2.redirectOutput(Redirect.INHERIT);
				Thread.sleep(1000);
				System.out.println(i + " did his vote.");
			}


			Thread.sleep(30000);
			
		} finally {
			if (pr1 != null) {
				pr1.destroy();
			}
			if (pr2 != null) {
				pr2.destroy();
			}
			if (pr3 != null) {
				pr3.destroy();
			}
		}
	}

	@Override
	protected void setUp() throws Exception {
//		super.setUp();
//		File f = new File(PKIServerCore.DEFAULT_DATABASE);
//		f.delete();
	}

}
