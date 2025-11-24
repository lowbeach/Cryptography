using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    // O Salt deve ser um array de bytes constante para este exemplo simples.
    // Em produção, o ideal é gerar um salt aleatório e salvar junto com o arquivo.
    private static readonly byte[] SALT = Encoding.ASCII.GetBytes("SuaAppDeCriptografiaSalt");

    static void Main(string[] args)
    {
        Console.WriteLine("=== Criptografia de Arquivos Simples ===");
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

    static void CriptografarArquivo(string arquivoEntrada, string senha)
    {
        string arquivoSaida = arquivoEntrada + ".enc";

        // Deriva a chave e o IV a partir da senha e do Salt
        using (var rfc = new Rfc2898DeriveBytes(senha, SALT, 10000, HashAlgorithmName.SHA256))
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = rfc.GetBytes(32); // Chave AES-256
                aes.IV = rfc.GetBytes(16);  // Vetor de inicialização

                using (FileStream fsSaida = new FileStream(arquivoSaida, FileMode.Create))
                {
                    // Escrevemos o IV no início do arquivo (público, necessário para descriptografar)
                    fsSaida.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cs = new CryptoStream(fsSaida, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        using (FileStream fsEntrada = new FileStream(arquivoEntrada, FileMode.Open))
                        {
                            fsEntrada.CopyTo(cs);                            
                        }                        
                    }
                }
            }
        }
        // Opcional: Deletar o arquivo original após criptografar
        File.Delete(arquivoEntrada); 
    }

    static void DescriptografarArquivo(string arquivoEntrada, string senha)
    {
        // Remove a extensão .enc para o nome final
        string arquivoSaida = arquivoEntrada.Substring(0, arquivoEntrada.Length - 4);

        using (FileStream fsEntrada = new FileStream(arquivoEntrada, FileMode.Open))
        {
            // Lê o IV que guardamos no início do arquivo
            byte[] iv = new byte[16];
            fsEntrada.Read(iv, 0, iv.Length);

            using (var rfc = new Rfc2898DeriveBytes(senha, SALT, 10000, HashAlgorithmName.SHA256))
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Key = rfc.GetBytes(32);
                    aes.IV = iv; // Usamos o IV lido do arquivo

                    using (CryptoStream cs = new CryptoStream(fsEntrada, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        using (FileStream fsSaida = new FileStream(arquivoSaida, FileMode.Create))
                        {
                            cs.CopyTo(fsSaida);                            
                        }                        
                    }
                }
            }
        }
        // Opcional: Deletar o arquivo criptografado após o sucesso
        File.Delete(arquivoEntrada);
    }
}
