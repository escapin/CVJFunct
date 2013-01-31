package de.uni.trier.infsec.lib.crypto;

import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Real implementation of same interface as environment.crypto.CryptoLib
 */
public class CryptoLib {

	private static final int pkKeySize 		= 1024; // 1024 Bits keysize
	private static final int nonce_length 	= 8; // 8 Bytes = 64 Bit nonce length

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public static byte[] pke_encrypt(byte[] message, byte[] publicKey) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			// for private keys use PKCS8EncodedKeySpec; for public keys use
			// X509EncodedKeySpec
			X509EncodedKeySpec ks = new X509EncodedKeySpec(publicKey);
			PublicKey pk = kf.generatePublic(ks);

			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			c.init(Cipher.ENCRYPT_MODE, pk);
			byte[] out = c.doFinal(message);
			return out;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] pke_decrypt(byte[] message, byte[] privKey) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			// for private keys use PKCS8EncodedKeySpec; for public keys use
			// X509EncodedKeySpec
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privKey);
			PrivateKey pk = kf.generatePrivate(ks);
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
			c.init(Cipher.DECRYPT_MODE, pk);
			byte[] out = c.doFinal(message);
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static KeyPair pke_generateKeyPair() {
		KeyPair out = new KeyPair();
		KeyPairGenerator keyPairGen;
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(pkKeySize);
			java.security.KeyPair pair = keyPairGen.generateKeyPair();
			out.privateKey = pair.getPrivate().getEncoded();
			out.publicKey = pair.getPublic().getEncoded();
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] sign(byte[] data, byte[] signingKey) {
		Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			// for private keys use PKCS8EncodedKeySpec;
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(signingKey);
			PrivateKey pk = kf.generatePrivate(ks);

			signer = Signature.getInstance("SHA256WithRSA", "BC");
			signer.initSign(pk);
			signer.update(data);
			return signer.sign();
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyException | SignatureException | InvalidKeySpecException e) {
			System.out.println("Signature creation failed " + e.getLocalizedMessage());
			return null;
		}
	}

	public static boolean verify(byte[] data, byte[] signature, byte[] verificationKey) {
		Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			// for private keys use PKCS8EncodedKeySpec; for public keys use
			// X509EncodedKeySpec
			X509EncodedKeySpec ks = new X509EncodedKeySpec(verificationKey);
			PublicKey pk = kf.generatePublic(ks);

			signer = Signature.getInstance("SHA256WithRSA", "BC");
			signer.initVerify(pk);
			signer.update(data);
			return signer.verify(signature);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | KeyException | SignatureException | InvalidKeySpecException e) {
			System.out.println("Signature verification failed " + e.getLocalizedMessage());
			return false;
		}
	}

	public static KeyPair generateSignatureKeyPair() {
		KeyPair out = new KeyPair();
		KeyPairGenerator keyPairGen;
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(pkKeySize);
			java.security.KeyPair pair = keyPairGen.generateKeyPair();
			out.privateKey = pair.getPrivate().getEncoded();
			out.publicKey = pair.getPublic().getEncoded();
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] generateNonce() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[nonce_length];
		random.nextBytes(bytes);
		return bytes;
	}

}
