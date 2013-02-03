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
		try {
			String cmd = "java";
			ProcessBuilder p1 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.functionalities.pki.real.PKIServer", "-DDEBUG=TRUE");
			ProcessBuilder p2 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.ServerStandalone", "-DDEBUG=TRUE");
			ProcessBuilder p3 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.BulletinBoardStandalone", "-DDEBUG=TRUE");
			ProcessBuilder p4 = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.protocols.smt_voting.VoterStandalone", "-DDEBUG=TRUE");

			p1.redirectErrorStream(true);
			p1.redirectOutput(Redirect.INHERIT);
			pr1 = p1.start();
			
			p2.redirectErrorStream(true);
			p2.redirectOutput(Redirect.INHERIT);
			pr2 = p2.start();

			Thread.sleep(10000);
			
		} finally {
			if (pr1 != null) {
				pr1.destroy();
			}
			if (pr2 != null) {
				pr2.destroy();
			}
		}
	}

	@Override
	protected void setUp() throws Exception {
		super.setUp();
		File f = new File(PKIServerCore.DEFAULT_DATABASE);
		f.delete();
	}

}
