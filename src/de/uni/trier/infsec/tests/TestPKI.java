package de.uni.trier.infsec.tests;

import java.io.File;
import java.io.IOException;
import java.lang.ProcessBuilder.Redirect;
import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.PKI;
import de.uni.trier.infsec.functionalities.pki.PKIServerCore;
import de.uni.trier.infsec.functionalities.pkienc.Decryptor;
import de.uni.trier.infsec.functionalities.pkienc.Encryptor;
import de.uni.trier.infsec.functionalities.pkienc.PKIError;
import de.uni.trier.infsec.functionalities.pkienc.RegisterEnc;
import de.uni.trier.infsec.functionalities.pkisig.Signer;
import de.uni.trier.infsec.functionalities.pkisig.Verifier;
import de.uni.trier.infsec.functionalities.pkisig.RegisterSig;
import de.uni.trier.infsec.functionalities.smt.SMT;
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
			ProcessBuilder p = new ProcessBuilder(cmd, "-cp", System.getProperties().getProperty("java.class.path", null), "de.uni.trier.infsec.functionalities.pki.PKIServerApp");
			p.redirectErrorStream(true);
			p.redirectOutput(Redirect.INHERIT);
			pr = p.start();

			PKI.useRemoteMode();

			Decryptor d1 = new Decryptor();
			RegisterEnc.registerEncryptor(d1.getEncryptor(), TEST_ID1, RegisterEnc.DEFAULT_PKI_DOMAIN);
			Decryptor d2 = new Decryptor();
			RegisterEnc.registerEncryptor(d2.getEncryptor(), TEST_ID2, RegisterEnc.DEFAULT_PKI_DOMAIN);

			Encryptor e1 = RegisterEnc.getEncryptor(TEST_ID1, RegisterEnc.DEFAULT_PKI_DOMAIN);
			Encryptor e2 = RegisterEnc.getEncryptor(TEST_ID2, RegisterEnc.DEFAULT_PKI_DOMAIN);
			
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
				Decryptor d = new Decryptor();
				RegisterEnc.registerEncryptor(d.getEncryptor(), TEST_ID1,RegisterEnc.DEFAULT_PKI_DOMAIN);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not throw an Error!", error);
			error = false;
			try {
				RegisterEnc.getEncryptor(99292, RegisterEnc.DEFAULT_PKI_DOMAIN);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown ID did not throw an Error!", error);
			
			error = false;
			try {
				RegisterEnc.getEncryptor(TEST_ID1, RegisterSig.DEFAULT_PKI_DOMAIN);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown Wrong domain did not lead to an error!", error);
			
			Signer s1 = new Signer();
			RegisterSig.registerVerifier(s1.getVerifier(), TEST_ID1, RegisterSig.DEFAULT_PKI_DOMAIN);
			Signer s2 = new Signer();
			RegisterSig.registerVerifier(s2.getVerifier(), TEST_ID2, RegisterSig.DEFAULT_PKI_DOMAIN);
			
			byte[] sig1 = s1.sign(TEST_DATA);
			byte[] sig2 = s2.sign(TEST_DATA);
			
			Verifier v1 = RegisterSig.getVerifier(TEST_ID1, RegisterSig.DEFAULT_PKI_DOMAIN);
			Verifier v2 = RegisterSig.getVerifier(TEST_ID2, RegisterSig.DEFAULT_PKI_DOMAIN);
			
			assertTrue("Verification of correct signature failed", v1.verify(sig1, TEST_DATA));
			assertTrue("Verification of correct signature failed", v2.verify(sig2, TEST_DATA));
			assertFalse("Verification of incorrect signature succeeded", v1.verify(sig2, TEST_DATA));
			assertFalse("Verification of incorrect signature succeeded", v2.verify(sig1, TEST_DATA));
			
			error = false;
			try {
				Signer s = new Signer();
				RegisterSig.registerVerifier(s.getVerifier(), TEST_ID1, RegisterSig.DEFAULT_PKI_DOMAIN);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Duplicate registration did not throw an Error!", error);
			error = false;
			try {
				RegisterSig.getVerifier(9292, RegisterSig.DEFAULT_PKI_DOMAIN);
			} catch (PKIError e) {
				error = true;
			}
			assertTrue("Unknown ID did not throw an Error!", error);
			
			error = false;
			try {
				RegisterSig.getVerifier(TEST_ID1, SMT.DOMAIN_SMT_ENCRYPTION);
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
