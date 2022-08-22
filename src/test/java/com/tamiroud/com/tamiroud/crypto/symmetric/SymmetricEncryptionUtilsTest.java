package com.tamiroud.com.tamiroud.crypto.symmetric;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;

class SymmetricEncryptionUtilsTest {

	@Test
	void createAESKey() throws NoSuchAlgorithmException {
		SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
		assertNotNull( secretKey );
		System.out.println( DatatypeConverter.printHexBinary( secretKey.getEncoded() ) );
	}

	@Test
	void testAESCryptoRoutine() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
		byte[] initializationVector = SymmetricEncryptionUtils.createInitializationVector();

		String plainText = "This is the text we are going to hide in plain sight";
		byte[] cipherText = SymmetricEncryptionUtils.performAESEncryption( plainText, secretKey, initializationVector );
		assertNotNull( cipherText );
		System.out.println( DatatypeConverter.printHexBinary( cipherText ) );

		String decryptedText = SymmetricEncryptionUtils.performAESDecryption( cipherText, secretKey, initializationVector );
		assertNotNull( decryptedText );
		System.out.println( decryptedText );
	}
}
