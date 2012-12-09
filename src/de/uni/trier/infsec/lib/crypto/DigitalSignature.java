package de.uni.trier.infsec.lib.crypto;

import java.security.KeyException;
import java.security.KeyFactory;
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DigitalSignature {
	
	// TODO: Also add functionalities Signer and Verifier ?
	// TODO: In which repository? Master AND/OR PKI?
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static byte[] sign(byte[] data, byte[] privKey) {
	    Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			//for private keys use PKCS8EncodedKeySpec;
			PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(privKey);
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
	
	public static boolean verify(byte[] data, byte[] signature, byte[] pubKey) {
	    Signature signer;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
			//for private keys use PKCS8EncodedKeySpec; for public keys use X509EncodedKeySpec
			X509EncodedKeySpec ks = new X509EncodedKeySpec(pubKey);
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
	
}
