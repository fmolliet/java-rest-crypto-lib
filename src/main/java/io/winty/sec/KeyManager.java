package io.winty.sec;

import java.security.GeneralSecurityException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyManager {
    private static final int DEK_KEY_SIZE = 256;
    private static final String ALGORITHM = "AES";

    public SecretKey generateDEK() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(DEK_KEY_SIZE);
        return keyGenerator.generateKey();
    }
}