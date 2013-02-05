package de.uni.trier.infsec.lib.test;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.real.PKIEnc;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc.Decryptor;
import de.uni.trier.infsec.functionalities.pki.real.PKIEnc.Encryptor;
import de.uni.trier.infsec.functionalities.pki.real.PKIError;
import de.uni.trier.infsec.functionalities.pki.real.PKIServerCore;
import de.uni.trier.infsec.functionalities.pki.real.PKISig;
import de.uni.trier.infsec.functionalities.pki.real.PKISig.Signer;
import de.uni.trier.infsec.functionalities.pki.real.PKISig.Verifier;
import de.uni.trier.infsec.functionalities.smt.real.SMT;
import de.uni.trier.infsec.lib.network.NetworkError;
import de.uni.trier.infsec.utils.Utilities;

public class TestPKI extends TestCase {

	public static int TEST_ID1  = 42424242;
	public static int TEST_ID2  = 43434343;
	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
	
	
	@Test
	public void testRealPKIRemote() throws PKIError, NetworkError, IOException {
		Process pr = null;
		try {
			String cmd = "java";
			ProcessBuilder p = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.functionalities.pki.real.PKIServer");
			p.redirectErrorStream(true);
			p.redirectOutput(Redirect.INHERIT);
			pr = p.start();

			System.setProperty("remotemode", Boolean.toString(true));

			Decryptor d1 = PKIEnc.register(TEST_ID1, PKIEnc.DOMAIN_ENCRYPTION);
			Decryptor d2 = PKIEnc.register(TEST_ID2, PKIEnc.DOMAIN_ENCRYPTION);

			Encryptor e1 = PKIEnc.getEncryptor(TEST_ID1, PKIEnc.DOMAIN_ENCRYPTION);
			Encryptor e2 = PKIEnc.getEncryptor(TEST_ID2, PKIEnc.DOMAIN_ENCRYPTION);
			
			System.err.println("plaintxt: " + Utilities.byteArrayToHexString(TEST_DATA));
			byte[] ctxt1 = e1.encrypt(TEST_DATA);
			System.err.println("ciphertxt: " + Utilities.byteArrayToHexString(ctxt1));
			byte[] ptxt = d1.decrypt(ctxt1);
			System.err.println("plaintxt: " + Utilities.byteArrayToHexString(ptxt));
			assertTrue("Plaintext has changed during encryption", Arrays.equals(ptxt, TEST_DATA));

			System.err.println("plaintxt: " + Utilities.byteArrayToHexString(TEST_DATA));
			byte[] ctxt2 = e2.encrypt(TEST_DATA);
			System.err.println("ciphertxt: " + Utilities.byteArrayToHexString(ctxt2));
			byte[] ptxt2 = d2.decrypt(ctxt2);
			System.err.println("plaintxt: " + Utilities.byteArrayToHexString(ptxt2));
			assertTrue("Plaintext has changed during encryption", Arrays.equals(ptxt2, TEST_DATA));

			boolean error = false;
			try {
				PKIEnc.register(TEST_ID1, PKIEnc.DOMAIN_ENCRYPTION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not throw an Error!", error);
			error = false;
			try {
				PKIEnc.getEncryptor(99292, PKIEnc.DOMAIN_ENCRYPTION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown ID did not throw an Error!", error);
			
			error = false;
			try {
				PKIEnc.getEncryptor(TEST_ID1, PKISig.DOMAIN_VERIFICATION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown Wrong domain did not lead to an error!", error);
			
			
			Signer s1 = PKISig.register(TEST_ID1, PKISig.DOMAIN_VERIFICATION);
			Signer s2 = PKISig.register(TEST_ID2, PKISig.DOMAIN_VERIFICATION);
			
			byte[] sig1 = s1.sign(TEST_DATA);
			byte[] sig2 = s2.sign(TEST_DATA);
			
			Verifier v1 = PKISig.getVerifier(TEST_ID1, PKISig.DOMAIN_VERIFICATION);
			Verifier v2 = PKISig.getVerifier(TEST_ID2, PKISig.DOMAIN_VERIFICATION);
			
			assertTrue("Verification of correct signature failed", v1.verify(sig1, TEST_DATA));
			assertTrue("Verification of correct signature failed", v2.verify(sig2, TEST_DATA));
			assertFalse("Verification of incorrect signature succeeded", v1.verify(sig2, TEST_DATA));
			assertFalse("Verification of incorrect signature succeeded", v2.verify(sig1, TEST_DATA));
			
			error = false;
			try {
				PKISig.register(TEST_ID1, PKISig.DOMAIN_VERIFICATION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not throw an Error!", error);
			error = false;
			try {
				PKISig.getVerifier(9292, PKISig.DOMAIN_VERIFICATION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown ID did not throw an Error!", error);
			
			error = false;
			try {
				PKISig.getVerifier(TEST_ID1, SMT.DOMAIN_SMT_ENCRYPTION);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown Wrong domain did not lead to an error!", error);
			
		} finally {
			if (pr != null) {
				pr.destroy();
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
