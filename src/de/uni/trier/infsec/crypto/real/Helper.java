package de.uni.trier.infsec.crypto.real;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import de.uni.trier.infsec.crypto.real.objects.Message;
import de.uni.trier.infsec.crypto.real.objects.key.DecryptionKey;
import de.uni.trier.infsec.crypto.real.objects.key.EncryptionKey;



public class Helper {
	
	public static final int STANDARD_PK_KEYSIZE = 128;
	public static final boolean debug = false;

	public static final String byteArrayToHexString(byte[] b) {
		final String hexChar = "0123456789ABCDEF";

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < b.length; i++)
		{
			sb.append(hexChar.charAt((b[i] >> 4) & 0x0f));
			sb.append(hexChar.charAt(b[i] & 0x0f));
		}
		return sb.toString();
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static final int byteArrayToInt(byte [] b) {
        return (b[0] << 24)
                + ((b[1] & 0xFF) << 16)
                + ((b[2] & 0xFF) << 8)
                + (b[3] & 0xFF);
	}
	

	public static final byte[] intToByteArray(int value) {
	        return new byte[] {
	                (byte)(value >>> 24),
	                (byte)(value >>> 16),
	                (byte)(value >>> 8),
	                (byte)value};
	}

	
	public static Thread runAsThread(Object object, String methodname) {
		Thread t = new GenericThread(object, methodname);
		t.start();
		return t;
	}
	
	static class GenericThread extends Thread {
		Object o;
		Method m;
		
		public GenericThread(Object obj, String method) {
			this.o = obj;
			try {
				m = o.getClass().getMethod(method, new Class[]{});
			} catch (SecurityException e) {
				e.printStackTrace();
			} catch (NoSuchMethodException e) {
				e.printStackTrace();
			}
		}
		
		@Override
		public void run() {
			try {
				m.invoke(o, new Object[]{});
			} catch (IllegalArgumentException e) {
				e.printStackTrace();
			} catch (IllegalAccessException e) {
				e.printStackTrace();
			} catch (InvocationTargetException e) {
				e.printStackTrace();
			}
		}
	}

	public static void writeToFile(String filename, byte[] data) throws IOException {
		FileOutputStream file = new FileOutputStream(filename);
		file.write(data);
		file.flush();
		file.close();		
	}
	
	public static EncryptionKey readPubKeyFromFile(String filename) throws Exception {
		File file = new File(filename);
		FileInputStream fiPubKey = new FileInputStream(file);
		
		byte[] key = new byte[(int) file.length()];
		fiPubKey.read(key);
		fiPubKey.close();
		KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA", "BC");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);  
	    RSAPublicKey rsaPubKey = (RSAPublicKey)rsaKeyFac.generatePublic(keySpec);
	    return new EncryptionKey(rsaPubKey);	
	}
	
	public static DecryptionKey readPrivKeyFromFile(String filename) throws Exception {
		File file = new File(filename);
		FileInputStream fiPrivKey = new FileInputStream(file);
		
		byte[] key = new byte[(int) file.length()];
		fiPrivKey.read(key);
		fiPrivKey.close();
		KeyFactory rsaKeyFac = KeyFactory.getInstance("RSA", "BC");  
		PKCS8EncodedKeySpec encodedPrivKeySpec = new PKCS8EncodedKeySpec(key);  
		return new DecryptionKey((RSAPrivateKey)rsaKeyFac.generatePrivate(encodedPrivKeySpec));
	}
	
	
	
	public static Message readMessageFromFile(String filename) throws Exception {
		File file = new File(filename);
		FileInputStream fiMsg = new FileInputStream(file);
		
		byte[] msg = new byte[(int) file.length()];
		fiMsg.read(msg);
		fiMsg.close();
		return Message.getMessageFromBytes(Message.TAG_DUMMY, msg);
	}
	
	
}
