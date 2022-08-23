package com.tamiroud.crypto.digitalsignature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public class DigitalSignatureUtils {

	public static final String SIGNING_ALGORITHM = "SHA256withRSA";

	public static byte[] createDigitalSignature( byte[] input, PrivateKey privateKey ) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature signature = Signature.getInstance( SIGNING_ALGORITHM );
		signature.initSign( privateKey );
		signature.update( input );
		return signature.sign();
	}

	public static boolean verifyDigitalSignature( byte[] input, byte[] signatureToVerify, PublicKey publicKey ) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		Signature signature = Signature.getInstance( SIGNING_ALGORITHM );
		signature.initVerify( publicKey );
		signature.update( input );
		return signature.verify( signatureToVerify );
	}
}
