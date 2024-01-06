# Documentação da Classe RestCrypto

## Visão Geral
`RestCrypto` é uma classe de utilidade Java projetada para fornecer funções de criptografia de repouso seguras. Ela usa o AES no modo Galois/Counter Mode (GCM) para garantir confidencialidade e integridade dos dados. A classe permite criptografar e descriptografar dados, bem como encapsular e desencapsular chaves de criptografia usando uma chave mestra (KEK).

## Como Configurar

### Pré-Requisitos
- Java Development Kit (JDK) versão 8 ou superior.
- Um ambiente de desenvolvimento ou servidor que suporte a execução de aplicativos Java.

### Instanciando a Classe
Para usar a `RestCrypto`, você deve instanciá-la com uma Key Encryption Key (KEK) codificada em Base64. A KEK é essencial para proteger a chave de dados (DEK) usada para criptografar e descriptografar as informações.

```java
String base64EncodedKek = "SuaKEKCodificadaEmBase64";
RestCrypto restCrypto = new RestCrypto(base64EncodedKek);
```

## Métodos Disponíveis

### storeSecureData
**Descrição**: Criptografa dados e encapsula a DEK usada para a criptografia.

**Parâmetros**:
- `data`: String representando os dados que precisam ser criptografados.

**Retorno**:
- String que representa os dados criptografados e a DEK encapsulada, ambos codificados em Base64.

**Uso**:
```java
String dadosParaCriptografar = "Informações sensíveis aqui";
String dadosCriptografados = restCrypto.storeSecureData(dadosParaCriptografar);
```

### retrieveSecureData
**Descrição**: Desencapsula a DEK e descriptografa os dados criptografados.

**Parâmetros**:
- `cipheredData`: String que representa os dados criptografados e a DEK encapsulada, ambos codificados em Base64.

**Retorno**:
- String representando os dados originais após a descriptografia.

**Uso**:
```java
String dadosDescriptografados = restCrypto.retrieveSecureData(dadosCriptografados);
```

## Considerações de Segurança
- Mantenha a KEK segura e confidencial. Qualquer pessoa com acesso à KEK poderá descriptografar os dados.
- Nunca use a mesma KEK para múltiplos propósitos ou em múltiplos sistemas.
- Garanta que a versão do seu JDK suporta criptografia AES-256. Algumas versões podem requerer a instalação de políticas de criptografia de força ilimitada.
- A segurança da criptografia também depende da segurança do ambiente onde a aplicação está sendo executada.

## Exemplo Completo
```java
public class Main {
    public static void main(String[] args) {
        try {
            String base64EncodedKek = "SuaKEKCodificadaEmBase64";
            RestCrypto restCrypto = new RestCrypto(base64EncodedKek);

            // Dados para criptografar
            String sensitiveData = "Dados sensíveis aqui";

            // Armazenando (criptografando) os dados
            String cipheredData = restCrypto.storeSecureData(sensitiveData);
            System.out.println("Dados Criptografados: " + cipheredData);

            // Recuperando (descriptografando) os dados
            String decryptedData = restCrypto.retrieveSecureData(cipheredData);
            System.out.println("Dados Descriptografados: " + decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## Manutenção e Suporte
Para questões, suporte ou contribuições, entre em contato com o mantenedor do projeto ou abra uma issue no repositório do projeto.