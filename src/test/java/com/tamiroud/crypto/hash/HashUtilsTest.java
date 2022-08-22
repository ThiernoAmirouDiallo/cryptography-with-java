package com.tamiroud.crypto.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;

class HashUtilsTest {

	@Test
	void generateRandomSalt() {
		byte[] salt = HashUtils.generateRandomSalt();
		assertNotNull( salt );
		System.out.println( DatatypeConverter.printHexBinary( salt ) );
	}

	@Test
	void createSHA2Hash() throws IOException, NoSuchAlgorithmException {
		byte[] salt = HashUtils.generateRandomSalt();
		byte[] hash = HashUtils.createSHA2Hash( "Input to hash", salt );
		assertNotNull( hash );
		byte[] hash2 = HashUtils.createSHA2Hash( "Input to hash", salt );
		assertEquals( DatatypeConverter.printHexBinary( hash ), DatatypeConverter.printHexBinary( hash2 ) );
		System.out.println( DatatypeConverter.printHexBinary( hash ) );
	}

	@Test
	void testBcryptRoutine() {
		String password = "to the moon from here";
		String passwordhash = HashUtils.getBcryptPasswordHash( password );
		System.out.println( passwordhash );
		assertTrue( HashUtils.verifyBcryptPasswordHash( password, passwordhash ) );
	}

	@Test
	void testPBKDF2Routine() throws NoSuchAlgorithmException, InvalidKeySpecException {
		String password = "to the moon from here";
		byte[] salt = HashUtils.generateRandomSalt();
		byte[] passwordhash = HashUtils.getPBKDF2PasswordHash( password, salt );
		System.out.println( DatatypeConverter.printHexBinary( passwordhash ) );
		assertTrue( HashUtils.verifyPBKDF2PasswordHash( password, passwordhash, salt ) );
	}

	@Test
	void testScryptRoutine() {
		String password = "to the moon from here";
		String passwordhash = HashUtils.getScryptPasswordHash( password );
		System.out.println( passwordhash );
		assertTrue( HashUtils.verifyScryptPasswordHash( password, passwordhash ) );
	}
}