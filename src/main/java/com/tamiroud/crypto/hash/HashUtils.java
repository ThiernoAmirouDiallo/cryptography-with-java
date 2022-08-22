package com.tamiroud.crypto.hash;

import com.lambdaworks.crypto.SCryptUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import at.favre.lib.crypto.bcrypt.BCrypt;

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

	public static String getBcryptPasswordHash( String password ) {
		// Bcrypt cost is exponential: 2^12
		return BCrypt.withDefaults().hashToString( 12, password.toCharArray() );
	}

	public static boolean verifyBcryptPasswordHash( String password, String hashedPassword ) {
		return BCrypt.verifyer().verify( password.toCharArray(), hashedPassword ).verified;
	}

	public static byte[] getPBKDF2PasswordHash( String password, byte[] salt ) throws NoSuchAlgorithmException, InvalidKeySpecException {
		// PBKDF2 cost is linear: 65536
		KeySpec spec = new PBEKeySpec( password.toCharArray(), salt, 65536, 128 );
		SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA1" );

		return factory.generateSecret( spec ).getEncoded();
	}

	public static boolean verifyPBKDF2PasswordHash( String password, byte[] hashedPassword, byte[] salt ) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeySpec spec = new PBEKeySpec( password.toCharArray(), salt, 65536, 128 );
		SecretKeyFactory factory = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA1" );
		byte[] generatedHash = factory.generateSecret( spec ).getEncoded();

		return Arrays.equals( hashedPassword, generatedHash );
	}

	public static String getScryptPasswordHash( String password ) {
		// Scrypt cost is expressed with
		// salt (autogenerated and appended to the hash here)
		// N: CPU cost parameter
		// r: Memory cost parameter
		// p: Parallelization parameter
		// dkLen: ouput hash length (32 in this implementation)
		return SCryptUtil.scrypt( password, 32, 16, 10 );
	}

	public static boolean verifyScryptPasswordHash( String password, String hashedPassword ) {
		return SCryptUtil.check( password, hashedPassword );
	}
}
