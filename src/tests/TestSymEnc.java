package tests;

import junit.framework.TestCase;

import org.junit.Test;

import funct.symenc.SymEnc;

import java.util.Arrays;

public class TestSymEnc extends TestCase {

	public static byte[] TEST_DATA = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
	
	@Test
	public void test() {
		SymEnc senc1 = new SymEnc();
		SymEnc senc2 = new SymEnc();
		
		byte[] encrypted1 = senc1.encrypt(TEST_DATA);
		byte[] encrypted2 = senc2.encrypt(TEST_DATA);
		byte[] encrypted3 = senc2.encrypt(TEST_DATA);
		
		// it should give different results:
		assertFalse( Arrays.equals(encrypted1, encrypted2) );
		assertFalse( Arrays.equals(encrypted1, encrypted3) );
		assertFalse( Arrays.equals(encrypted2, encrypted3) );
		
		// decryption should revert encryption:
		byte[] decrypted1 = senc1.decrypt(encrypted1);
		assertTrue(Arrays.equals(TEST_DATA, decrypted1));
	}

}
