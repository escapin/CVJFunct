package de.unitrier.infsec.tests;

import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.unitrier.infsec.functionalities.pkenc.Decryptor;
import de.unitrier.infsec.functionalities.pkenc.Encryptor;
import de.unitrier.infsec.functionalities.digsig.Signer;
import de.unitrier.infsec.functionalities.digsig.Verifier;
import de.unitrier.infsec.utils.Utilities;

public class TestAsymEnc extends TestCase {

	public static byte[] TEST_DATA = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
	
	@Test
	public void testAsymEnc() {
		Decryptor d1 = new Decryptor();
		Decryptor d2 = new Decryptor();
		
		Encryptor e1 = d1.getEncryptor();
		Encryptor e2 = d2.getEncryptor();
		
		System.out.println("plaintxt: " + Utilities.byteArrayToHexString(TEST_DATA));
		byte[] ctxt1 = e1.encrypt(TEST_DATA);
		System.err.println("ciphertxt: " + Utilities.byteArrayToHexString(ctxt1));
		byte[] ptxt = d1.decrypt(ctxt1);
		System.out.println("plaintxt: " + Utilities.byteArrayToHexString(ptxt));
		assertTrue("Plaintext has changed during encryption", Arrays.equals(ptxt, TEST_DATA));
		
		System.out.println();
			
		System.out.println("plaintxt: " + Utilities.byteArrayToHexString(TEST_DATA));
		byte[] ctxt2 = e2.encrypt(TEST_DATA);
		System.err.println("ciphertxt: " + Utilities.byteArrayToHexString(ctxt2));
		byte[] ptxt2 = d2.decrypt(ctxt2);
		System.out.println("plaintxt: " + Utilities.byteArrayToHexString(ptxt2));
		assertTrue("Plaintext has changed during encryption", Arrays.equals(ptxt2, TEST_DATA));

		// boolean error = false;
		
		Signer s1 = new Signer();
		Signer s2 = new Signer();
		
		Verifier v1 = s1.getVerifier();
		Verifier v2 = s2.getVerifier();
		
		byte[] sig1 = s1.sign(TEST_DATA);
		byte[] sig2 = s2.sign(TEST_DATA);
		
		
		assertTrue("Verification of correct signature failed", v2.verify(sig2, TEST_DATA));
		assertFalse("Verification of incorrect signature succeeded", v1.verify(sig2, TEST_DATA));
		assertFalse("Verification of incorrect signature succeeded", v2.verify(sig1, TEST_DATA));
	}

}
