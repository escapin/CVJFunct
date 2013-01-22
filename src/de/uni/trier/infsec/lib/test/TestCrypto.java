package de.uni.trier.infsec.lib.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.lib.crypto.CryptoLib;
import de.uni.trier.infsec.lib.crypto.DigitalSignature;
import de.uni.trier.infsec.lib.crypto.KeyPair;

public class TestCrypto extends TestCase {

	
	public static byte[] TEST_DATA = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	
	@Test
	public void testPKEnc() {
		
		KeyPair kp = CryptoLib.pke_generateKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		
		byte[] enc = CryptoLib.pke_encrypt(TEST_DATA, pubKey);
		byte[] dec = CryptoLib.pke_decrypt(enc, privKey);
		
		assertTrue(Arrays.equals(TEST_DATA, dec));
	}
	
	@Test
	public void testSignature() {
		KeyPair kp = CryptoLib.generateSignatureKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		
		byte[] signature = DigitalSignature.sign(TEST_DATA, privKey);
		
		assertTrue(DigitalSignature.verify(TEST_DATA, signature, pubKey));
		signature[0] ++;
		assertFalse(DigitalSignature.verify(TEST_DATA, signature, pubKey));
	}
	
}
