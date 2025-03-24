package com.cgutman.adblib;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class STLSUtils {
    private static final String KEY_ALIAS = "my_key_alias";

    public static void generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setKeySize(2048)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .setCertificateSubject(new X500Principal("CN=Sample Name"))
                            .setCertificateSerialNumber(BigInteger.ONE)
                            .setCertificateNotBefore(new Date())
                            .setCertificateNotAfter(Date.from(ZonedDateTime.now().plusYears(25).toInstant()))
                            .build());
        }

        keyPairGenerator.generateKeyPair();
    }

    public static void getKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEY_ALIAS, null);
        java.security.PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
        java.security.PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        System.out.println("Public Key: " + publicKey);
        System.out.println("Private Key: " + privateKey);
    }

    public static KeyPair generateRSAKeyPair_() throws NoSuchAlgorithmException {
        // Initialize the KeyPairGenerator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        // Specify the key size
        keyPairGenerator.initialize(2048);

        // Generate the key pair
        return keyPairGenerator.generateKeyPair();
    }
}
