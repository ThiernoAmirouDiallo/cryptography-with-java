package com.tamiroud.crypto.digitalsignature;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.tamiroud.crypto.asymmetric.AsymmetricEncryptionUtils;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import javax.xml.bind.DatatypeConverter;

import org.junit.jupiter.api.Test;

class DigitalSignatureUtilsTest {

	@Test
	void digitalSignatureRoutine() throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		String messageToSign = "This is the electronic message to sign to encore it has not been changed";

		KeyPair keyPair = AsymmetricEncryptionUtils.generateRSAKeyPair();
		byte[] signature = DigitalSignatureUtils.createDigitalSignature( messageToSign.getBytes(), keyPair.getPrivate() );
		assertNotNull( signature );
		System.out.println( DatatypeConverter.printHexBinary( signature ) );
		assertTrue( DigitalSignatureUtils.verifyDigitalSignature( messageToSign.getBytes(), signature, keyPair.getPublic() ) );
	}
}