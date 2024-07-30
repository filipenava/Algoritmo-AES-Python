"""
Módulo para encriptação e decriptação de mensagens usando o algoritmo AES.

Este módulo contém várias funções que implementam as operações básicas do
algoritmo AES, como substituição de bytes, deslocamento de linhas, mistura
de colunas, adição de chave de rodada e expansão de chave. Ele também inclui
funções para encriptar e decriptar mensagens, além de funções auxiliares para
gerar chaves aleatórias e manipular arquivos.

Autor: Filipe Nava
Professor: Ronaldo Toshiaki Oikawa


Descrição do Código:

Bibliotecas Importadas
-random e string são importadas para geração de chaves aleatórias.

Variáveis Globais:
-Sbox: Substituição de bytes usada durante a encriptação.
-Rcon: Constantes usadas na expansão da chave.

Funções Principais:
-gerar_chave(tamanho=16): Gera uma chave aleatória de tamanho especificado.
-sub_bytes(state): Substitui bytes na matriz de estado usando a S-Box.
-inv_sub_bytes(state): Substitui bytes na matriz de estado usando a inversa da S-Box.
-shift_rows(state): Aplica a operação Shift Rows.
-inv_shift_rows(state): Aplica a operação inversa de Shift Rows.
-mix_columns(state): Aplica a operação Mix Columns.
-inv_mix_columns(state): Aplica a operação inversa de Mix Columns.
-add_round_key(state, round_key): Adiciona a chave da rodada à matriz de estado.
-key_expansion(key): Expande a chave para as rodadas do algoritmo AES.
-xtime(a): Multiplica um valor no campo finito.
-encrypt_block(plain_block, key): Encripta um bloco de texto plano.
-decrypt_block(cipher_block, key): Decripta um bloco de texto cifrado.
-encrypt(message, key): Encripta uma mensagem.
-decrypt(ciphertext, key): Decripta uma mensagem cifrada.
-salvar_mensagem_encriptada(ciphertext, arquivo): Salva a mensagem encriptada em um arquivo.
-ler_mensagem_encriptada(arquivo): Lê a mensagem encriptada de um arquivo.

"""

import random
import string

# S-Box utilizado na substituição de bytes durante a encriptação
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Rcon usado na expansão de chave (constantes de rodada)
Rcon = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
]

def gerar_chave(tamanho=16):
    """
    Gera uma chave aleatória de tamanho especificado (em bytes).

    :param tamanho: Tamanho da chave em bytes (default é 16)
    :return: Chave gerada como bytes
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=tamanho)).encode('utf-8')

def sub_bytes(state):
    """
    Aplica a substituição de bytes na matriz de estado usando a S-Box.

    :param state: Matriz de estado
    """
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j]]

def inv_sub_bytes(state):
    """
    Aplica a substituição inversa de bytes na matriz de estado usando a inversa da S-Box.

    :param state: Matriz de estado
    """
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[Sbox[i]] = i
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]

def shift_rows(state):
    """
    Aplica a operação Shift Rows na matriz de estado.

    :param state: Matriz de estado
    """
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

def inv_shift_rows(state):
    """
    Aplica a operação inversa de Shift Rows na matriz de estado.

    :param state: Matriz de estado
    """
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

def mix_columns(state):
    """
    Aplica a operação Mix Columns na matriz de estado.

    :param state: Matriz de estado
    """
    for i in range(4):
        t = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3]
        u = state[i][0]
        state[i][0] ^= t ^ xtime(state[i][0] ^ state[i][1])
        state[i][1] ^= t ^ xtime(state[i][1] ^ state[i][2])
        state[i][2] ^= t ^ xtime(state[i][2] ^ state[i][3])
        state[i][3] ^= t ^ xtime(state[i][3] ^ u)

def inv_mix_columns(state):
    """
    Aplica a operação inversa de Mix Columns na matriz de estado.

    :param state: Matriz de estado
    """
    for i in range(4):
        u = xtime(xtime(state[i][0] ^ state[i][2]))
        v = xtime(xtime(state[i][1] ^ state[i][3]))
        state[i][0] ^= u
        state[i][1] ^= v
        state[i][2] ^= u
        state[i][3] ^= v
    mix_columns(state)

def add_round_key(state, round_key):
    """
    Adiciona a chave da rodada à matriz de estado.

    :param state: Matriz de estado
    :param round_key: Chave da rodada
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]

def key_expansion(key):
    """
    Expande a chave para uso nas rodadas do algoritmo AES.

    :param key: Chave inicial
    :return: Chaves expandidas para cada rodada
    """
    key_symbols = [b for b in key]
    if len(key_symbols) < 4 * 4:
        for i in range(4 * 4 - len(key_symbols)):
            key_symbols.append(0x01)
    key_schedule = [[0] * 4 for _ in range(44)]
    for r in range(4):
        for c in range(4):
            key_schedule[r][c] = key_symbols[r + c * 4]
    for row in range(4, 4 * 11):
        temp = [key_schedule[row - 1][i] for i in range(4)]
        if row % 4 == 0:
            temp = [Sbox[temp[(i + 1) % 4]] for i in range(4)]
            temp[0] ^= Rcon[row // 4]
        for i in range(4):
            key_schedule[row][i] = key_schedule[row - 4][i] ^ temp[i]
    return key_schedule

def xtime(a):
    """
    Multiplica um valor no campo finito (usado no Mix Columns).

    :param a: Valor a ser multiplicado
    :return: Resultado da multiplicação
    """
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

def encrypt_block(plain_block, key):
    """
    Encripta um bloco de texto plano.

    :param plain_block: Bloco de texto plano
    :param key: Chave de encriptação
    :return: Bloco de texto cifrado
    """
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = plain_block[r + 4 * c]
    
    round_keys = key_expansion(key)
    add_round_key(state, round_keys[:4])
    
    for round in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round * 4:(round + 1) * 4])
    
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10 * 4:])
    
    cipher_block = [state[r][c] for c in range(4) for r in range(4)]
    return bytes(cipher_block)

def decrypt_block(cipher_block, key):
    """
    Decripta um bloco de texto cifrado.

    :param cipher_block: Bloco de texto cifrado
    :param key: Chave de decriptação
    :return: Bloco de texto plano
    """
    state = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            state[r][c] = cipher_block[r + 4 * c]
    
    round_keys = key_expansion(key)
    add_round_key(state, round_keys[10 * 4:])
    
    for round in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round * 4:(round + 1) * 4])
        inv_mix_columns(state)
    
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[:4])
    
    plain_block = [state[r][c] for c in range(4) for r in range(4)]
    return bytes(plain_block)

def encrypt(message, key):
    """
    Encripta uma mensagem.

    :param message: Mensagem a ser encriptada
    :param key: Chave de encriptação
    :return: Mensagem cifrada
    """
    message = message + (16 - len(message) % 16) * chr(16 - len(message) % 16)
    cipher_blocks = []
    
    for i in range(0, len(message), 16):
        block = message[i:i + 16].encode('utf-8')
        cipher_block = encrypt_block(block, key)
        cipher_blocks.append(cipher_block)
    
    return b''.join(cipher_blocks)

def decrypt(ciphertext, key):
    """
    Decripta uma mensagem cifrada.

    :param ciphertext: Mensagem cifrada
    :param key: Chave de decriptação
    :return: Mensagem decriptada
    """
    plain_blocks = []
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plain_block = decrypt_block(block, key)
        plain_blocks.append(plain_block)
    
    plaintext = b''.join(plain_blocks)
    pad_len = plaintext[-1]
    return plaintext[:-pad_len].decode('utf-8', errors='ignore')

def salvar_mensagem_encriptada(ciphertext, arquivo):
    """
    Salva a mensagem encriptada em um arquivo.

    :param ciphertext: Mensagem cifrada
    :param arquivo: Nome do arquivo
    """
    try:
        with open(arquivo, 'wb') as file:
            file.write(ciphertext)
    except IOError as e:
        print(f"Erro ao salvar a mensagem encriptada: {e}")

def ler_mensagem_encriptada(arquivo):
    """
    Lê a mensagem encriptada de um arquivo.

    :param arquivo: Nome do arquivo
    :return: Mensagem cifrada ou None em caso de erro
    """
    try:
        with open(arquivo, 'rb') as file:
            ciphertext = file.read()
        return ciphertext
    except IOError as e:
        print(f"Erro ao ler a mensagem encriptada: {e}")
        return None
