# vernamcifra


Aluno: Roger Stroff Leites (mat: 2023007875)
Trabalho: Cifra de Vernam

A cifra de Vernam basicamente utiliza uma operação XOR (^) para criptografar dados.

#Entrada de dados:
Na função main são passados três parâmetros (args[0], args[1] e args[2]: <arquivo.txt>, <senha> e <criptografar> (ou <decriptografar>);
Conforme o caso (modo), o arquivo é criptografado ou decriptografado.

#Derivação da chave:
Na função gerarChave, a chave é derivada da senha fornecida através do algoritmo PBKDF2 com HMAC-SHA256.
O tamanho da chave é de 256 bits.

#Cifragem (Vernam XOR):
Na função cifrar é usada a cifra de vernam, que essencialmente realiza uma opração XOR byte a byte com a chave.
Recebe como parâmetros uma array de bytes contendo dos dados em binário do arquivo e um array de bytes da chave.

#Modo Criptografar:
Passa o conteúdo do arquivo (plaintext) para um array de bytes.
Gera um salt aleatório.
Deriva a chave a partir da senha e do salt.
Executa a função cifar
Gera um arquivo de saída contendo o salt e o conteúdo criptografado (arquivo_cifrado.txt).

#Modo decriptografar:
Passa o conteúdo do arquivo (ciphertext) para um array de bytes.
Extrai o salt armazenado no arquivo.
Deriva a mesma chave utilizando a senha e o salt.
Executa a mesma função cifrar para reverter a operação XOR.
Gera um arquivo de saída com o conteúdo original(arquivo_decifrado.txt).
