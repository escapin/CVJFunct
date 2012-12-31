package de.uni.trier.infsec.lib.test;

import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.lib.crypto.CryptoLib;

public class TestCrypto extends TestCase {

	
	public static byte[] TEST_DATA = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	
	@Test
	public void testCrypto() {
		
		KeyPair kp = CryptoLib.pke_generateKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		
		byte[] enc = CryptoLib.pke_encrypt(TEST_DATA, pubKey);
		byte[] dec = CryptoLib.pke_decrypt(enc, privKey);
		
		assertTrue(Arrays.equals(TEST_DATA, dec));
	}
	
	@Test
	public void testSignature() {
		KeyPair kp = CryptoLib.pke_generateKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		
		byte[] signature = CryptoLib.ds_sign(TEST_DATA, privKey);
		
		assertTrue(CryptoLib.ds_verify(TEST_DATA, signature, pubKey));
		signature[0] ++;
		assertFalse(CryptoLib.ds_verify(TEST_DATA, signature, pubKey));
	}
	
}
