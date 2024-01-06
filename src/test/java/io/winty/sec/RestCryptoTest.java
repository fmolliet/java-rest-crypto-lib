package io.winty.sec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class RestCryptoTest {
    
    private RestCrypto rest;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        // Inicializar o serviço de criptografia
        rest = new RestCrypto("n3hPQcSOyOgbtDdmY2LvabvMa20XA3dhO7Cokb2kBdk=");
    }
    
    @Test
    void testEncryptionDecryptionGCM() {
        String originalText = "Texto de teste secreto";
        try {
            // Criptografar o texto original
            String encryptedText = rest.storeSecureData(originalText);
            // Descriptografar o texto criptografado
            String decryptedText = rest.retrieveSecureData(encryptedText);
            // Verificar se o texto descriptografado é igual ao texto original
            assertEquals(originalText, decryptedText);
        } catch (Exception e) {
            fail("Exceção lançada durante teste de criptografia/descriptografia: " + e.getMessage());
        }
    }

    @Test
    void testDecryptWithInvalidData() {
        String invalidData = "dados_invalidos";
        assertThrows(Exception.class, () -> {
            // Tentar descriptografar dados inválidos deve lançar uma exceção
            rest.retrieveSecureData(invalidData);
        });
    }
}
