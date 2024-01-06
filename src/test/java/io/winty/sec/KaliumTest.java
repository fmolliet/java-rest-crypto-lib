package io.winty.sec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
 
public class KaliumTest {
    private Kalium kalium;

    @BeforeEach
    void setUp() {
        System.setProperty("APP_KEK", "your_test_kek_here");
        kalium = new Kalium();
    }

    @Test
    @Disabled
    void testEncryptionDecryption() {
        String originalText = "Texto de teste secreto";
        try {
            String encryptedText = kalium.encrypt(originalText);
            String decryptedText = kalium.decrypt(encryptedText);
            assertEquals(originalText, decryptedText);
        } catch (Exception e) {
            fail("Exceção lançada durante teste de criptografia/descriptografia: " + e.getMessage());
        }
    }

    @Test
    @Disabled
    void testDecryptWithInvalidData() {
        String invalidData = "dados_invalidos";
        assertThrows(Exception.class, () -> {
            // Tentar descriptografar dados inválidos deve lançar uma exceção
            kalium.decrypt(invalidData);
        });
    }
}
