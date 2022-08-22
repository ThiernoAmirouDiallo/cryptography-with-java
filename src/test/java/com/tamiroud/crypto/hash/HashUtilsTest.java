package com.tamiroud.crypto.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

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

}