# Trabalho Algoritmo AES Python - Segurança da Informação

## Pesquisa e construção de um algoritmo

**Professor:** Ronaldo Toshiaki Oikawa  
**Aluno:** Filipe Nava  

### Objetivo
Este projeto visa a pesquisa e implementação de algoritmos de criptografia. A tarefa inclui um resumo sobre várias criptografias e a implementação de uma delas em Python 3.x.

### Criptografias Pesquisadas
- DES
- 3DES
- Blowfish
- AES
- SAFER

Cada criptografia foi explicada com pelo menos meia página de conteúdo, utilizando a formatação padrão Arial 12, espaçamento 1,5.

### Algoritmo Implementado
Escolhi implementar o algoritmo AES (Advanced Encryption Standard). Foram criadas duas versões do programa:

- **V1:** Utilizando a biblioteca `pycryptodome` do Python 3.x.
- **V2:** Construindo a própria biblioteca.

### Descrição dos Arquivos

#### Versão 1: Utilizando a Biblioteca `pycryptodome`
Arquivo: `aes_crypto_with_pycryptodome.py`

Este arquivo contém:
- Funções para encriptar e decriptar mensagens usando AES no modo EAX.
- Funções para salvar e ler mensagens encriptadas de arquivos.
- Interação com o usuário utilizando a biblioteca `rich` para melhorar a interface no console.

**Instalação das Dependências:**

#### pip install pycryptodome rich

#### Uso:
Execute o script aes_crypto_with_pycryptodome.py para interagir com o programa no console.

Versão 2: Construindo a Própria Biblioteca
Arquivo: aes_crypto.py

#### Este arquivo contém:

Implementação completa do algoritmo AES com funções para substituição de bytes, deslocamento de linhas, mistura de colunas, adição de chave de rodada e expansão de chave.

Funções para encriptar e decriptar blocos de mensagens e manipulação de arquivos.

#### Uso:
Execute o script aes_crypto_main.py para interagir com o programa no console.

### Como Executar
#### Versão 1
##### python aes_crypto_with_pycryptodome.py

#### Versão 2

##### python aes_crypto_main.py

Estrutura do Projeto
.
├── README.md
├── aes_crypto.py
├── aes_crypto_main.py
└── aes_crypto_with_pycryptodome.py







