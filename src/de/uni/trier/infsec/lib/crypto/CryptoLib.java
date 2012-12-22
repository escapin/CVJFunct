package de.uni.trier.infsec.lib.crypto;

import java.security.KeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.sun.org.apache.xml.internal.security.utils.HelperNodeList;

import de.uni.trier.infsec.environment.crypto.KeyPair;
import de.uni.trier.infsec.utils.MessageTools;
import de.uni.trier.infsec.utils.Utilities;

public class CryptoLib {

	private static final int pkKeySize = 1024;

	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String[] args) {
		 KeyPair kp = CryptoLib.ds_generateKeyPair();
		 System.out.println(Utilities.byteArrayToHexString(kp.publicKey));
		 System.out.println(Utilities.byteArrayToHexString(kp.privateKey));
	}

	public static byte[] pke_encrypt(byte[] message, byte[] publicKey) {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			//for private keys use PKCS8EncodedKeySpec; for public keys use X509EncodedKeySpec
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
			//for private keys use PKCS8EncodedKeySpec; for public keys use X509EncodedKeySpec
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
			out.publicKey  = pair.getPublic().getEncoded();
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	
	// TODO: Also add functionalities Signer and Verifier ?
	// TODO: In which repository? Master AND/OR PKI?
	// TODO: ideal/PKI: Make ideal testable?! --> Enough to exchange cryptolib?
	// TODO: real/PKI: Do we want a switch for "RPC-server/RPC-client/LOCAL"?  
	// TODO: How to sign? Server signs Keys, Users verify? "byte level" or "Verifier.verify(Signature, Encryptor)"
	
	
	public static byte[] ds_sign(byte[] data, byte[] signingKey) {
	    Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			//for private keys use PKCS8EncodedKeySpec;
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
	
	public static boolean ds_verify(byte[] data, byte[] signature, byte[] verificationKey) {
	    Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			//for private keys use PKCS8EncodedKeySpec; for public keys use X509EncodedKeySpec
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
	
	public static KeyPair ds_generateKeyPair() {
		KeyPair out = new KeyPair();
		KeyPairGenerator keyPairGen;
		try {
			keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(pkKeySize);
			java.security.KeyPair pair = keyPairGen.generateKeyPair();
			out.privateKey = pair.getPrivate().getEncoded();
			out.publicKey  = pair.getPublic().getEncoded();
			return out;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
