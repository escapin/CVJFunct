package de.uni.trier.infsec.lib.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.functionalities.pki.real.PKI;
import de.uni.trier.infsec.functionalities.pki.real.PKI.Decryptor;

public class TestPKI extends TestCase {
	
	public static byte[] TEST_ID1 = {0x11, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	public static byte[] TEST_DATA = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

	@Test
	public void testRealPKIRemote() {
		System.setProperty("localmode", Boolean.toString(false));
		Decryptor d1 = PKI.register(TEST_ID1);
		
		byte[] ctxt1 = d1.getEncryptor().encrypt(TEST_DATA);
		byte[] ptxt = d1.decrypt(ctxt1);
		assertTrue("Plaintext has changed during encryption", Arrays.equals(ptxt, TEST_DATA));
	}
	
	
	
}
