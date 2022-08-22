package com.tamiroud.com.tamiroud.crypto.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class SymmetricEncryptionUtils {

	public static final String AES = "AES";
	public static final String AES_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	public static final int AES_KEY_SIZE = 256;

	public static SecretKey createAESKey() throws NoSuchAlgorithmException {
		SecureRandom secureRandom = new SecureRandom();
		KeyGenerator keyGenerator = KeyGenerator.getInstance( AES );
		keyGenerator.init( AES_KEY_SIZE, secureRandom );
		return keyGenerator.generateKey();
	}

	public static byte[] createInitializationVector() {
		byte[] initializationVector = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes( initializationVector );
		return initializationVector;
	}

	public static byte[] performAESEncryption( String plainText, SecretKey secretKey, byte[] initilizationVector )
			throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance( AES_CIPHER_ALGORITHM );
		IvParameterSpec ivParameterSpec = new IvParameterSpec( initilizationVector );
		cipher.init( Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec );
		return cipher.doFinal( plainText.getBytes() );
	}

	public static String performAESDecryption( byte[] cipherText, SecretKey secretKey, byte[] initilizationVector )
			throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance( AES_CIPHER_ALGORITHM );
		IvParameterSpec ivParameterSpec = new IvParameterSpec( initilizationVector );
		cipher.init( Cipher.DECRYPT_MODE, secretKey, ivParameterSpec );
		byte[] result = cipher.doFinal( cipherText );
		return new String( result );
	}
}
