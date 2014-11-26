package de.unitrier.infsec.tests;

import junit.framework.TestCase;

import org.junit.Test;

import java.util.Arrays;

import de.unitrier.infsec.functionalities.nonce.NonceGen;

public class TestNonces extends TestCase {
	@Test
	public void testNonces()  {
		NonceGen gen1 = new NonceGen();
		NonceGen gen2 = new NonceGen();
		byte[] nonce1 = gen1.nextNonce();
		byte[] nonce2 = gen1.nextNonce();
		byte[] nonce3 = gen2.nextNonce();
		byte[] nonce4 = gen2.nextNonce();
		assertFalse("Nonce collision", Arrays.equals(nonce1, nonce2));
		assertFalse("Nonce collision", Arrays.equals(nonce1, nonce3));
		assertFalse("Nonce collision", Arrays.equals(nonce1, nonce4));
		assertFalse("Nonce collision", Arrays.equals(nonce2, nonce3));
		assertFalse("Nonce collision", Arrays.equals(nonce2, nonce4));
		assertFalse("Nonce collision", Arrays.equals(nonce3, nonce4));
	}
}
