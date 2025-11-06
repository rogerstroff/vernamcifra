import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;

public class VernamCifra {

    //Deriva uma chave PBKDF2 a partir da senha e salt
    private static byte[] gerarChave(String senha, byte[] salt, int tamanhoBits) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(senha.toCharArray(), salt, 65536, tamanhoBits);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return skf.generateSecret(spec).getEncoded();
    }

    //Vernam XOR
    public static byte[] cifrar(byte[] dados, byte[] chave) {
        byte[] xored = new byte[dados.length];
        for (int i = 0; i < dados.length; i++) {
            xored[i] = (byte) (dados[i] ^ chave[i % chave.length]);
        }
        return xored;
    }

    //Criptografar
    private static void criptografar(String arquivo, String senha) throws Exception {
        byte[] conteudo = Files.readAllBytes(Paths.get(arquivo));

        // Gera salt aleatório
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] chave = gerarChave(senha, salt, 256);
        byte[] cifrado = cifrar(conteudo, chave);

        // Guarda salt no arquivo cifrado (base64)
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(salt);
        out.write(cifrado);

        Files.write(Paths.get("arquivo_cifrado.txt"), Base64.getEncoder().encode(out.toByteArray()));
        System.out.println("Arquivo cifrado gerado: arquivo_cifrado.txt");
    }

    //Decriptografar
    private static void decriptografar(String arquivo, String senha) throws Exception {
        byte[] dadosBase64 = Files.readAllBytes(Paths.get(arquivo));
        byte[] dados = Base64.getDecoder().decode(dadosBase64);

        // Extrai o salt (primeiros 16 bytes)
        byte[] salt = new byte[16];
        System.arraycopy(dados, 0, salt, 0, 16);

        byte[] cifrado = new byte[dados.length - 16];
        System.arraycopy(dados, 16, cifrado, 0, cifrado.length);

        byte[] chave = gerarChave(senha, salt, 256);
        byte[] decifrado = cifrar(cifrado, chave);

        Files.write(Paths.get("arquivo_decifrado.txt"), decifrado);
        System.out.println("Arquivo decifrado gerado: arquivo_decifrado.txt");
    }

    public static void main(String[] args) {
        try {
            if (args.length != 3) {
                System.err.println("Uso: java VernamCifra <arquivo.txt> <senha> <criptografar|decriptografar>");
                System.exit(1);
            }

            String arquivo = args[0];
            String senha = args[1];
            String modo = args[2].toLowerCase();

            if (modo.equals("criptografar")) {
                criptografar(arquivo, senha);
            }
            
            else if (modo.equals("decriptografar")) {
                decriptografar(arquivo, senha);
            }
            
            else {
                System.err.println("Modo inválido. Use 'criptografar' ou 'decriptografar'.");
                System.exit(1);
            }

        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            e.printStackTrace();
        }
    }
}