using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    // Tamanhos fixos para os elementos que vamos guardar no arquivo.
    private const int SaltSize = 16;
    private const int IvSize = 16; // AES usa um IV de 16 bytes
    private const int HmacSize = 32; // HMACSHA256 produz 32 bytes

    // Total de dados de controle adicionados: Salt + IV + HMAC = 64 bytes
    private const int HeaderAndFooterSize = SaltSize + IvSize + HmacSize;

    static void Main(string[] args)
    {
        // (A lógica Main() do programa anterior fica aqui, solicitando opção, caminho e senha)
        Console.WriteLine("=== Criptografia Avançada ===");
        Console.WriteLine("1. Criptografar Pasta");
        Console.WriteLine("2. Descriptografar Pasta");
        Console.Write("Escolha uma opção: ");
        var opcao = Console.ReadLine();

        Console.Write("Digite o caminho da pasta: ");
        string path = Console.ReadLine();

        Console.Write("Digite a senha: ");
        string senha = Console.ReadLine();

        if (!Directory.Exists(path))
        {
            Console.WriteLine("Pasta não encontrada!");
            return;
        }

        try
        {
            string[] arquivos = Directory.GetFiles(path);

            foreach (var arquivo in arquivos)
            {
                if (opcao == "1")
                {
                    // Evita criptografar o que já está criptografado
                    if (!arquivo.EndsWith(".enc"))
                    {
                        CriptografarArquivo(arquivo, senha);
                        Console.WriteLine($"Criptografado: {Path.GetFileName(arquivo)}");
                    }
                }
                else if (opcao == "2")
                {
                    // Só tenta descriptografar arquivos .enc
                    if (arquivo.EndsWith(".enc"))
                    {
                        DescriptografarArquivo(arquivo, senha);
                        Console.WriteLine($"Descriptografado: {Path.GetFileName(arquivo)}");
                    }
                }
            }
            Console.WriteLine("\nProcesso concluído!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erro: {ex.Message}");
        }
}

    // --- Métodos de Ajuda de Criptografia ---

    // Gera a Chave (Key) a partir da Senha e do Salt
    private static byte[] DeriveKey(string senha, byte[] salt)
    {
        // Rfc2898DeriveBytes (PBKDF2) é a função padrão para gerar chaves fortes a partir de senhas.
        // O número de iterações (100.000) torna o ataque de força bruta muito lento.
        using (var pbkdf2 = new Rfc2898DeriveBytes(senha, salt, 100000, HashAlgorithmName.SHA256))
        {
            // Retorna uma chave de 32 bytes (256 bits), ideal para AES.
            return pbkdf2.GetBytes(32);
        }
    }

    // --- Implementação do Nível 1 e 2 ---

    static void CriptografarArquivo(string arquivoEntrada, string senha)
    {
        string arquivoSaida = arquivoEntrada + ".enc";

        // 1. Geração de Parâmetros
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize); // Nível 1: Salt Único e Aleatório
        byte[] key = DeriveKey(senha, salt);
        byte[] iv;

        // Utilizamos um MemoryStream para segurar os dados criptografados
        // e calcular o HMAC antes de escrever no disco.
        using (var outputMemory = new MemoryStream())
        using (var aes = Aes.Create())
        {
            aes.Key = key;
            // O IV será gerado pela implementação do Aes e deve ser salvo!
            iv = aes.IV;

            // Criptografamos para a memória (outputMemory)
            using (var encryptor = aes.CreateEncryptor())
            using (var cs = new CryptoStream(outputMemory, encryptor, CryptoStreamMode.Write))
            {
                using (var fsEntrada = new FileStream(arquivoEntrada, FileMode.Open, FileAccess.Read))
                {
                    fsEntrada.CopyTo(cs);
                }
            }

            // 2. Calculando o HMAC (Nível 2)
            byte[] ciphertext = outputMemory.ToArray();
            byte[] hmacTag;

            // Usamos a mesma Key (chave de criptografia) para gerar o HMAC
            using (var hmac = new HMACSHA256(key))
            {
                // Calculamos o HMAC sobre os dados CRIPTOGRAFADOS (Ciphertext)
                hmacTag = hmac.ComputeHash(ciphertext);
            }

            // 3. Escrevendo no Disco (Estrutura: Salt + IV + HMAC + Ciphertext)
            using (var fsSaida = new FileStream(arquivoSaida, FileMode.Create, FileAccess.Write))
            {
                fsSaida.Write(salt, 0, SaltSize);
                fsSaida.Write(iv, 0, IvSize);
                fsSaida.Write(hmacTag, 0, HmacSize);
                fsSaida.Write(ciphertext, 0, ciphertext.Length);
            }
        }

        // Deletar o arquivo original com segurança
        File.Delete(arquivoEntrada);
    }

    static void DescriptografarArquivo(string arquivoEntrada, string senha)
    {
        // Nome de saída sem a extensão .enc
        string arquivoSaida = arquivoEntrada.Substring(0, arquivoEntrada.Length - 4);

        using (var fsEntrada = new FileStream(arquivoEntrada, FileMode.Open, FileAccess.Read))
        {
            if (fsEntrada.Length < HeaderAndFooterSize)
                throw new CryptographicException("Arquivo criptografado inválido ou corrompido.");

            // 1. Lendo o Cabeçalho (Salt, IV, HMAC Tag)
            byte[] salt = new byte[SaltSize];
            byte[] iv = new byte[IvSize];
            byte[] hmacTag = new byte[HmacSize];

            fsEntrada.Read(salt, 0, SaltSize);
            fsEntrada.Read(iv, 0, IvSize);
            fsEntrada.Read(hmacTag, 0, HmacSize);

            // O Key deve ser derivado do Salt lido do arquivo.
            byte[] key = DeriveKey(senha, salt);

            // 2. Verificação de Integridade (HMAC)
            byte[] calculatedHmac;

            // Calculamos o HMAC do que RESTOU do arquivo (o Ciphertext)
            using (var hmac = new HMACSHA256(key))
            {
                // Usamos um CryptoStream para calcular o Hash sobre o restante dos dados
                calculatedHmac = hmac.ComputeHash(fsEntrada);
            }

            // Compara o HMAC lido do arquivo com o que calculamos
            if (!CompareByteArrays(hmacTag, calculatedHmac))
            {
                // Se a senha estiver errada, esta verificação falhará!
                throw new CryptographicException("Senha Incorreta ou Arquivo adulterado!");
            }

            // 3. Decriptografia (Se a senha e a integridade estiverem corretas)

            // Reabrimos o arquivo, pulando o cabeçalho, para dar o stream de dados para o Aes
            using (var fsData = new FileStream(arquivoEntrada, FileMode.Open, FileAccess.Read))
            {
                // Posiciona o ponteiro de leitura após o cabeçalho (Salt + IV + HMAC)
                fsData.Seek(HeaderAndFooterSize, SeekOrigin.Begin);

                using (var aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (var decryptor = aes.CreateDecryptor())
                    using (var cs = new CryptoStream(fsData, decryptor, CryptoStreamMode.Read))
                    {
                        using (var fsSaida = new FileStream(arquivoSaida, FileMode.Create, FileAccess.Write))
                        {
                            cs.CopyTo(fsSaida);
                        }
                    }
                }
            }
        }
        // Se tudo deu certo, deleta o arquivo .enc
        File.Delete(arquivoEntrada);
    }

    // Método auxiliar para comparação segura de arrays de bytes
    private static bool CompareByteArrays(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}