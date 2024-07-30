"""
Módulo para encriptação e decriptação de mensagens usando a biblioteca PyCryptodome e Rich para melhorar a interface do usuário.

Este módulo contém funções para encriptar e descriptar mensagens, salvar e ler mensagens encriptadas em arquivos, e uma função principal para interagir com o usuário através do console.

Autor: Filipe Nava
Professor: Ronaldo Toshiaki Oikawa

Descrição do Código

Para que o código fornecido funcione corretamente, você precisará instalar as seguintes bibliotecas:

** PyCryptodome: Biblioteca para criptografia AES.
** Rich: Biblioteca para melhorar a saída no console.

Você pode instalar essas bibliotecas usando pip com os seguintes comandos:

** pip install pycryptodome
** pip install rich

Bibliotecas Importadas:
-Crypto.Cipher e Crypto.Random: Módulos da biblioteca PyCryptodome para criptografia AES e geração de bytes aleatórios.
-rich.console, rich.panel, rich.prompt, rich.text: Módulos da biblioteca Rich para melhorar a interface do usuário no console.

Funções Principais:
-encriptar_mensagem(mensagem, chave): Encripta uma mensagem usando AES no modo EAX.
-descriptar_mensagem(nonce, ciphertext, tag, chave): Descripta uma mensagem usando AES no modo EAX.
-salvar_mensagem_encriptada(nonce, ciphertext, tag, arquivo): Salva a mensagem encriptada em um arquivo.
-ler_mensagem_encriptada(arquivo): Lê a mensagem encriptada de um arquivo.

Função Principal:
-main(): Interage com o usuário para encriptar ou decriptar mensagens e salvar/ler arquivos cifrados, utilizando a biblioteca Rich para melhorar a experiência no console.

"""

from Crypto.Cipher import AES  # Biblioteca para criptografia AES
from Crypto.Random import get_random_bytes  # Função para gerar bytes aleatórios
from rich.console import Console  # Biblioteca Rich para melhorar a saída no console
from rich.panel import Panel  # Painel da biblioteca Rich para formatar texto
from rich.prompt import Prompt  # Biblioteca Rich para obter entrada do usuário
from rich.text import Text  # Biblioteca Rich para manipulação de texto

console = Console()  # Inicializa o console Rich

def encriptar_mensagem(mensagem, chave):
    """
    Encripta uma mensagem usando AES no modo EAX.

    :param mensagem: Mensagem a ser encriptada
    :param chave: Chave de encriptação (16 bytes)
    :return: nonce, texto cifrado e tag de autenticação
    """
    cipher = AES.new(chave, AES.MODE_EAX)  # Cria um objeto de cifra AES no modo EAX
    nonce = cipher.nonce  # Obtém o nonce (número aleatório único) usado na cifra
    ciphertext, tag = cipher.encrypt_and_digest(mensagem.encode('utf-8'))  # Encripta a mensagem e gera um tag de autenticação
    return nonce, ciphertext, tag  # Retorna o nonce, o texto cifrado e o tag

def descriptar_mensagem(nonce, ciphertext, tag, chave):
    """
    Descripta uma mensagem usando AES no modo EAX.

    :param nonce: Nonce usado durante a encriptação
    :param ciphertext: Texto cifrado
    :param tag: Tag de autenticação
    :param chave: Chave de encriptação (16 bytes)
    :return: Mensagem descriptada ou mensagem de erro
    """
    cipher = AES.new(chave, AES.MODE_EAX, nonce=nonce)  # Cria um objeto de cifra AES no modo EAX com o nonce fornecido
    mensagem = cipher.decrypt(ciphertext)  # Descripta o texto cifrado
    try:
        cipher.verify(tag)  # Verifica a integridade da mensagem com o tag
        return mensagem.decode('utf-8')  # Retorna a mensagem descriptada se a verificação for bem-sucedida
    except ValueError:
        return "Chave incorreta ou mensagem corrompida"  # Retorna um erro se a verificação falhar

def salvar_mensagem_encriptada(nonce, ciphertext, tag, arquivo):
    """
    Salva a mensagem encriptada em um arquivo.

    :param nonce: Nonce usado durante a encriptação
    :param ciphertext: Texto cifrado
    :param tag: Tag de autenticação
    :param arquivo: Nome do arquivo para salvar a mensagem encriptada
    """
    try:
        with open(arquivo, 'wb') as file:  # Abre o arquivo para escrita em modo binário
            file.write(nonce)  # Escreve o nonce no arquivo
            file.write(tag)  # Escreve o tag no arquivo
            file.write(ciphertext)  # Escreve o texto cifrado no arquivo
    except IOError as e:
        console.print(f"[red]Erro ao salvar a mensagem encriptada:[/red] {e}")  # Imprime um erro se a operação falhar

def ler_mensagem_encriptada(arquivo):
    """
    Lê a mensagem encriptada de um arquivo.

    :param arquivo: Nome do arquivo contendo a mensagem encriptada
    :return: nonce, texto cifrado e tag de autenticação ou None em caso de erro
    """
    try:
        with open(arquivo, 'rb') as file:  # Abre o arquivo para leitura em modo binário
            nonce = file.read(16)  # Lê os primeiros 16 bytes como nonce
            tag = file.read(16)  # Lê os próximos 16 bytes como tag
            ciphertext = file.read()  # Lê o restante do arquivo como texto cifrado
        return nonce, ciphertext, tag  # Retorna o nonce, o texto cifrado e o tag
    except IOError as e:
        console.print(f"[red]Erro ao ler a mensagem encriptada:[/red] {e}")  # Imprime um erro se a operação falhar
        return None, None, None  # Retorna None em caso de erro

def main():
    """
    Função principal que coordena a interação com o usuário para encriptar e descriptar mensagens.
    """
    console.print(Panel.fit("[bold yellow]Trabalho de Segurança da Informação[/bold yellow]\n\n"
                            "[bold]Realizado por:[/bold] Filipe Nava\n"
                            "[bold]Professor:[/bold] Ronaldo Toshiaki Oikawa", title="Informações do Trabalho"))

    while True:
        acao = Prompt.ask("\nVocê deseja [bold green]criar uma mensagem encriptada[/bold green] (1) ou [bold blue]ler uma mensagem encriptada[/bold blue] (2)?", choices=["1", "2"], default="1")
        
        if acao == '1':
            mensagem = Prompt.ask("Digite a mensagem a ser encriptada")  # Pede ao usuário para digitar a mensagem
            chave = get_random_bytes(16)  # Gera uma chave aleatória de 16 bytes
            nonce, ciphertext, tag = encriptar_mensagem(mensagem, chave)  # Encripta a mensagem com a chave gerada
            
            nome_arquivo = Prompt.ask("Digite o nome do arquivo para salvar a mensagem encriptada")  # Pede ao usuário para digitar o nome do arquivo
            salvar_mensagem_encriptada(nonce, ciphertext, tag, nome_arquivo)  # Salva a mensagem encriptada no arquivo
            
            console.print(Panel(f"[green]Mensagem encriptada salva no arquivo [bold]{nome_arquivo}[/bold][/green]\n"
                                f"Chave para decriptação (guarde com segurança): [bold]{chave.hex()}[/bold]", title="Sucesso"))
            
        elif acao == '2':
            nome_arquivo = Prompt.ask("Digite o nome do arquivo que contém a mensagem encriptada")  # Pede ao usuário para digitar o nome do arquivo
            chave_hex = Prompt.ask("Digite a chave para decriptação (em formato hexadecimal)")  # Pede ao usuário para digitar a chave em formato hexadecimal
            
            try:
                chave = bytes.fromhex(chave_hex)  # Converte a chave de hexadecimal para bytes
                nonce, ciphertext, tag = ler_mensagem_encriptada(nome_arquivo)  # Lê a mensagem encriptada do arquivo
                
                if nonce and ciphertext and tag:
                    mensagem_decriptada = descriptar_mensagem(nonce, ciphertext, tag, chave)  # Descripta a mensagem
                    console.print(Panel(f"Mensagem decriptada: [bold]{mensagem_decriptada}[/bold]", title="Mensagem Decriptada"))
                else:
                    console.print(Panel("[red]Não foi possível ler a mensagem encriptada.[/red]", title="Erro"))
                
            except ValueError:
                console.print(Panel("[red]Formato de chave inválido. Certifique-se de que está em hexadecimal.[/red]", title="Erro"))
                
        else:
            console.print(Panel("[red]Ação inválida.[/red]", title="Erro"))
        
        nova_acao = Prompt.ask("Você deseja realizar outra operação? (s/n)", choices=["s", "n"], default="s").lower()
        if nova_acao != 's':
            break

if __name__ == "__main__":
    main()  # Executa a função principal se o script for executado diretamente
