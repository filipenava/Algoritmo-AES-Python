"""
Autor: Filipe Nava
Professor: Ronaldo Toshiaki Oikawa


Descrição do Código:

Função Principal:
-main(): Interage com o usuário para encriptar ou decriptar mensagens e salvar/ler arquivos cifrados.

"""

import aes_crypto

def main():
    """
    Função principal para interagir com o usuário.
    """
    print("Trabalho de Segurança da Informação\n")
    print("Realizado por: Filipe Nava")
    print("Professor: Ronaldo Toshiaki Oikawa\n")

    while True:
        acao = input("Você deseja criar uma mensagem encriptada (1) ou ler uma mensagem encriptada (2)? ")
        
        if acao == '1':
            mensagem = input("Digite a mensagem a ser encriptada: ")
            chave = aes_crypto.gerar_chave(16)
            ciphertext = aes_crypto.encrypt(mensagem, chave)
            
            nome_arquivo = input("Digite o nome do arquivo para salvar a mensagem encriptada: ")
            aes_crypto.salvar_mensagem_encriptada(ciphertext, nome_arquivo)
            
            print(f"Mensagem encriptada salva no arquivo {nome_arquivo}")
            print(f"Chave para decriptação (guarde com segurança): {chave.decode('utf-8')}")
            
        elif acao == '2':
            nome_arquivo = input("Digite o nome do arquivo que contém a mensagem encriptada: ")
            chave = input("Digite a chave para decriptação: ").encode('utf-8')
            
            ciphertext = aes_crypto.ler_mensagem_encriptada(nome_arquivo)
            
            if ciphertext:
                mensagem_decriptada = aes_crypto.decrypt(ciphertext, chave)
                print(f"Mensagem decriptada: {mensagem_decriptada}")
            else:
                print("Não foi possível ler a mensagem encriptada.")
                
        else:
            print("Ação inválida.")
        
        nova_acao = input("Você deseja realizar outra operação? (s/n): ").lower()
        if nova_acao != 's':
            break

if __name__ == "__main__":
    main()
