package com.tamiroud.com.tamiroud.crypto.asymmetric;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricEncryptionUtils {

	private static final String RSA = "RSA";

	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( RSA );
		keyPairGenerator.initialize( 4096, secureRandom );
		return keyPairGenerator.generateKeyPair();
	}

	public static byte[] performRSAEncryption( String plainText, Key key )
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance( RSA );
		cipher.init( Cipher.ENCRYPT_MODE, key );
		return cipher.doFinal( plainText.getBytes() );
	}

	public static String performRSADecryption( byte[] cipherText, Key key )
			throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance( RSA );
		cipher.init( Cipher.DECRYPT_MODE, key );
		byte[] result = cipher.doFinal( cipherText );
		return new String( result );
	}

}
