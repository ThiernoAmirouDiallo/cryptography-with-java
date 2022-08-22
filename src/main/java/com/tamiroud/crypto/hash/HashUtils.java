package com.tamiroud.crypto.hash;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HashUtils {

	private static final String SHA2_ALGORITHM = "SHA-256";

	public static byte[] generateRandomSalt() {
		byte[] salt = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes( salt );
		return salt;
	}

	public static byte[] createSHA2Hash( String input, byte[] salt ) throws IOException, NoSuchAlgorithmException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		byteArrayOutputStream.write( salt );
		byteArrayOutputStream.write( input.getBytes() );
		byte[] valueToHash = byteArrayOutputStream.toByteArray();

		MessageDigest messageDigest = MessageDigest.getInstance( SHA2_ALGORITHM );
		return messageDigest.digest( valueToHash );
	}
}
