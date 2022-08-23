package com.tamiroud.crypto.keystore;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

public class KeyStoreUtils {

	public static final String SECRET_KEY_STORE_TYPE = "JCEKS";

	public static KeyStore createKeyStore( String keystorePassword, String keyAlias, SecretKey secretKey, String secretKeyPassword )
			throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
		KeyStore keyStore = KeyStore.getInstance( SECRET_KEY_STORE_TYPE );
		keyStore.load( null, keystorePassword.toCharArray() );
		KeyStore.ProtectionParameter passwordProtection = new KeyStore.PasswordProtection( secretKeyPassword.toCharArray() );
		KeyStore.SecretKeyEntry privateKeyEntry = new KeyStore.SecretKeyEntry( secretKey );
		keyStore.setEntry( keyAlias, privateKeyEntry, passwordProtection );
		return keyStore;
	}

	public static SecretKey getSecretKey( KeyStore keyStore, String keystorePassword, String keyAlias, String secretKeyPassword )
			throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
		keyStore.load( null, keystorePassword.toCharArray() );
		KeyStore.ProtectionParameter passwordProtection = new KeyStore.PasswordProtection( secretKeyPassword.toCharArray() );
		KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry( keyAlias, passwordProtection );
		return keyEntry.getSecretKey();
	}
}
