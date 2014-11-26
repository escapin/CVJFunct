package de.unitrier.infsec.tests;

import java.util.Arrays;

import junit.framework.TestCase;

import org.junit.Test;

import de.unitrier.infsec.lib.crypto.CryptoLib;
import de.unitrier.infsec.lib.crypto.KeyPair;

public class TestCrypto extends TestCase {
	
	public static byte[] TEST_DATA = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

	
	@Test
	public void testSymEnc() {
		// Key generation is not deterministic:
		byte[] key  =  CryptoLib.symkey_generateKey();
		byte[] key2 =  CryptoLib.symkey_generateKey();
		assertFalse( Arrays.equals(key, key2) );
		
		// Encryption + Decryption returns the original message:
		byte[] ciphertext = CryptoLib.symkey_encrypt(key, TEST_DATA);
		byte[] plaintext = CryptoLib.symkey_decrypt(key, ciphertext);
		assertTrue(Arrays.equals(TEST_DATA, plaintext));
		
		// Encryption is not deterministic:
		byte[] ciphertext2 = CryptoLib.symkey_encrypt(key, TEST_DATA);
		assertFalse( "Encryption is deterministic",  
				     Arrays.equals(ciphertext, ciphertext2) );
		
		// Decryption+Encryption also works for big data:
		byte[] big_message = new byte[100000];
		for(int i=0; i<100000; ++i) big_message[i] = (byte)(i%256);
		byte[] big_ciphertext = CryptoLib.symkey_encrypt(key, big_message);
		byte[] big_plaintext  = CryptoLib.symkey_decrypt(key, big_ciphertext);
		assertTrue(Arrays.equals(big_message, big_plaintext));
		
		// Authenticated encryption should not accept a changed ciphertext:
		int len = ciphertext.length;
		ciphertext[len-2] += 1; // modify one byte of the ciphertext
		byte[] result = CryptoLib.symkey_decrypt(key, ciphertext);
		assertTrue(result == null);
	}
	
	@Test
	public void testPKEnc() {
		KeyPair kp = CryptoLib.pke_generateKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		byte[] big_message = new byte[100000];
		for(int i=0; i<100000; ++i) big_message[i] = (byte)(i%256);
		byte[] big_ciphertext = CryptoLib.pke_encrypt(big_message, pubKey);
		byte[] big_plaintext  = CryptoLib.pke_decrypt(big_ciphertext, privKey);
		assertTrue(Arrays.equals(big_message, big_plaintext));
	}
	
	@Test
	public void testSignature() {
		KeyPair kp = CryptoLib.generateSignatureKeyPair();
		byte[] pubKey = kp.publicKey;
		byte[] privKey = kp.privateKey;
		
		byte[] signature = CryptoLib.sign(TEST_DATA, privKey);
		
		assertTrue(CryptoLib.verify(TEST_DATA, signature, pubKey));
		signature[0] ++;
		assertFalse(CryptoLib.verify(TEST_DATA, signature, pubKey));

	}
	
}
