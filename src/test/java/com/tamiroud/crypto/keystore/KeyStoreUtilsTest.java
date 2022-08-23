package com.tamiroud.crypto.keystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.tamiroud.crypto.symmetric.SymmetricEncryptionUtils;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyStoreUtilsTest {

	@Test
	void createPrivateJaveKeyStore() throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableEntryException {
		SecretKey secretKey = SymmetricEncryptionUtils.createAESKey();
		KeyStore keyStore = KeyStoreUtils.createKeyStore( "ksPasword", "foo", secretKey, "skPassword" );
		Assertions.assertNotNull( keyStore );

		SecretKey result = KeyStoreUtils.getSecretKey( keyStore, "ksPasword", "foo", "skPassword" );

		assertArrayEquals( result.getEncoded(), secretKey.getEncoded() );
	}
}