package com.tamiroud.com.tamiroud.crypto.asymmetric;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class AsymmetricEncryptionUtilsTest {

	public static Stream<Arguments> keyPairParams() throws NoSuchAlgorithmException {
		// asymmetric encryption works both ways: private key can decrypt public key cipher text and vice versa
		KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();

		return Stream.of( //
				Arguments.of( keyPair.getPrivate(), keyPair.getPublic() ), //
				Arguments.of( keyPair.getPublic(), keyPair.getPrivate() ) );

	}

	@Test
	void generateRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
		assertNotNull( keyPair );
		System.out.printf( "Private Key: %s%n", DatatypeConverter.printHexBinary( keyPair.getPrivate().getEncoded() ) );
		System.out.printf( "Public Key: %s%n", DatatypeConverter.printHexBinary( keyPair.getPublic().getEncoded() ) );
	}

	@ParameterizedTest()
	@MethodSource("keyPairParams")
	void testRSACryptRoutine( Key key1, Key key2 ) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		String plainText = "This is the text we are going to hide in plain sight with RSA";
		byte[] cipherText = AsymmetricEncryptionUtils.performRSAEncryption( plainText, key1 );
		assertNotNull( cipherText );
		System.out.println( DatatypeConverter.printHexBinary( cipherText ) );
		String decryptedText = AsymmetricEncryptionUtils.performRSADecryption( cipherText, key2 );
		System.out.println( decryptedText );
	}
}