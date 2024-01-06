package io.winty.sec;


import java.util.Base64;

import org.abstractj.kalium.crypto.Random;
import org.abstractj.kalium.keys.KeyPair;
import org.abstractj.kalium.NaCl;
import org.abstractj.kalium.crypto.SecretBox;

public class Kalium {
    
    private static final String KEK_ENV_VARIABLE = "APP_KEK"; // Nome da variável de ambiente onde a KEK está armazenada
    private final byte[] kek;
    
    public Kalium() {
        NaCl.init();

        String encodedKek = System.getenv(KEK_ENV_VARIABLE);
        if (encodedKek == null) {
            throw new IllegalStateException("KEK não definida na variável de ambiente " + KEK_ENV_VARIABLE);
        }
        this.kek = Base64.getDecoder().decode(encodedKek);
    }
    
    public String encrypt(String data) throws Exception {
        KeyPair keyPair = new KeyPair();
        
        SecretBox box = new SecretBox(keyPair.getPrivateKey().toBytes());

        byte[] nonce = new Random().randomBytes();

        byte[] encryptedData = box.encrypt(nonce, data.getBytes());

        byte[] encryptedDek = concat(kek, keyPair.getPrivateKey().toBytes());

        return Base64.getEncoder().encodeToString(nonce) + ":" + 
               Base64.getEncoder().encodeToString(encryptedDek) + ":" + 
               Base64.getEncoder().encodeToString(encryptedData);
    }
    
    public String decrypt(String encryptedDataWithDek) throws Exception {
        String[] parts = encryptedDataWithDek.split(":");
        byte[] nonce = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedDek = Base64.getDecoder().decode(parts[1]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[2]);

        // Separa a KEK e DEK
        byte[] dek = new byte[encryptedDek.length - kek.length];
        System.arraycopy(encryptedDek, kek.length, dek, 0, dek.length);

        SecretBox box = new SecretBox(dek);
        byte[] decryptedData = box.decrypt(nonce, encryptedData);

        return new String(decryptedData);
    }
    
    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}
