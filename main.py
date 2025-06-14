import rsa
import os

# --- Configurações ---
ARQUIVO_CHAVE_PUBLICA_B = "chave_publica_b.pem"
ARQUIVO_CHAVE_PRIVADA_B = "chave_privada_b.pem" # Sua chave privada, MANTENHA EM SEGREDO!
ARQUIVO_MENSAGEM_CRIPTOGRAFADA = "mensagem_cripto.txt" # Recebido da Equipe A
ARQUIVO_ASSINATURA = "assinatura.bin"               # Recebido da Equipe A
ARQUIVO_CHAVE_PUBLICA_A = "chave_publica_a.pem"      # Recebido da Equipe A
ARQUIVO_MENSAGEM_DESCRIPTOGRAFADA = "mensagem_recebida.txt"
ARQUIVO_RESULTADO_ASSINATURA = "assinatura_verificada.txt" # Opcional, para registro

def gerar_chaves_b():
    """Gera um par de chaves RSA (pública e privada) para a Equipe B."""
    if os.path.exists(ARQUIVO_CHAVE_PRIVADA_B) and os.path.exists(ARQUIVO_CHAVE_PUBLICA_B):
        print("Chaves da Equipe B já existem. Pulando a geração.")
        with open(ARQUIVO_CHAVE_PUBLICA_B, 'rb') as f:
            pubkey_b = rsa.PublicKey.load_pkcs1(f.read())
        with open(ARQUIVO_CHAVE_PRIVADA_B, 'rb') as f:
            privkey_b = rsa.PrivateKey.load_pkcs1(f.read())
        return pubkey_b, privkey_b

    print("Gerando chaves RSA para a Equipe B...")
    (pubkey_b, privkey_b) = rsa.newkeys(2048) # Chaves de 2048 bits

    with open(ARQUIVO_CHAVE_PUBLICA_B, 'wb') as f:
        f.write(pubkey_b.save_pkcs1('PEM'))
    with open(ARQUIVO_CHAVE_PRIVADA_B, 'wb') as f:
        f.write(privkey_b.save_pkcs1('PEM'))
    print(f"Chave pública da Equipe B salva em: {ARQUIVO_CHAVE_PUBLICA_B}")
    print(f"Chave privada da Equipe B salva em: {ARQUIVO_CHAVE_PRIVADA_B}")
    return pubkey_b, privkey_b

def carregar_chaves():
    """Carrega as chaves privadas da Equipe B e pública da Equipe A."""
    try:
        with open(ARQUIVO_CHAVE_PRIVADA_B, 'rb') as f:
            privkey_b = rsa.PrivateKey.load_pkcs1(f.read())
        print(f"Chave privada da Equipe B carregada de: {ARQUIVO_CHAVE_PRIVADA_B}")
    except FileNotFoundError:
        print(f"ERRO: O arquivo '{ARQUIVO_CHAVE_PRIVADA_B}' não foi encontrado.")
        print("Certifique-se de ter suas chaves geradas e este arquivo salvo.")
        exit()
    except Exception as e:
        print(f"ERRO ao carregar a chave privada da Equipe B: {e}")
        exit()

    try:
        with open(ARQUIVO_CHAVE_PUBLICA_A, 'rb') as f:
            pubkey_a = rsa.PublicKey.load_pkcs1(f.read())
        print(f"Chave pública da Equipe A carregada de: {ARQUIVO_CHAVE_PUBLICA_A}")
    except FileNotFoundError:
        print(f"ERRO: O arquivo '{ARQUIVO_CHAVE_PUBLICA_A}' (chave pública da Equipe A) não foi encontrado.")
        print("Certifique-se de que a Equipe A lhe enviou a chave pública dela.")
        exit()
    except Exception as e:
        print(f"ERRO ao carregar a chave pública da Equipe A: {e}")
        exit()

    return privkey_b, pubkey_a

def descriptografar_e_verificar(privkey_b, pubkey_a):
    """Descriptografa a mensagem e verifica a assinatura."""
    # 1. Carregar a mensagem criptografada
    try:
        with open(ARQUIVO_MENSAGEM_CRIPTOGRAFADA, 'rb') as f:
            cripto_mensagem = f.read()
        print(f"Mensagem criptografada lida de: {ARQUIVO_MENSAGEM_CRIPTOGRAFADA}")
    except FileNotFoundError:
        print(f"ERRO: O arquivo '{ARQUIVO_MENSAGEM_CRIPTOGRAFADA}' não foi encontrado.")
        print("Certifique-se de ter recebido a mensagem criptografada da Equipe A.")
        exit()

    # 2. Carregar a assinatura
    try:
        with open(ARQUIVO_ASSINATURA, 'rb') as f:
            assinatura = f.read()
        print(f"Assinatura lida de: {ARQUIVO_ASSINATURA}")
    except FileNotFoundError:
        print(f"ERRO: O arquivo '{ARQUIVO_ASSINATURA}' não foi encontrado.")
        print("Certifique-se de ter recebido a assinatura da Equipe A.")
        exit()

    # 3. Descriptografar a mensagem
    print("Descriptografando mensagem com sua chave privada...")
    try:
        mensagem_descriptografada = rsa.decrypt(cripto_mensagem, privkey_b).decode('utf-8')
        with open(ARQUIVO_MENSAGEM_DESCRIPTOGRAFADA, 'w', encoding='utf-8') as f:
            f.write(mensagem_descriptografada)
        print(f"Mensagem descriptografada salva em: {ARQUIVO_MENSAGEM_DESCRIPTOGRAFADA}")
        print("\n--- Conteúdo da Mensagem Original ---")
        print(mensagem_descriptografada)
        print("------------------------------------")
    except rsa.DecryptionError:
        print("ERRO DE DESCRIPTOGRAFIA: A mensagem não pode ser descriptografada.")
        print("Isso pode ocorrer se a chave privada estiver incorreta ou a mensagem foi corrompida.")
        exit()
    except Exception as e:
        print(f"ERRO durante a descriptografia: {e}")
        exit()

    # 4. Verificar a assinatura
    print("\nVerificando assinatura digital com a chave pública da Equipe A...")
    verificacao_resultado = "FALHA NA VERIFICAÇÃO!"
    try:
        # A verificação usa o conteúdo ORIGINAL da mensagem (antes de ser criptografada),
        # que é o que acabamos de descriptografar.
        rsa.verify(mensagem_descriptografada.encode('utf-8'), assinatura, pubkey_a)
        verificacao_resultado = "SUCESSO! A assinatura é VÁLIDA."
        print("A mensagem é autêntica e não foi alterada.")
    except rsa.VerificationError:
        verificacao_resultado = "FALHA NA VERIFICAÇÃO! A assinatura é INVÁLIDA."
        print("Atenção: A mensagem pode ter sido alterada ou não foi enviada pela Equipe A.")
    except Exception as e:
        print(f"ERRO durante a verificação da assinatura: {e}")
        verificacao_resultado = f"ERRO na verificação: {e}"

    with open(ARQUIVO_RESULTADO_ASSINATURA, 'w', encoding='utf-8') as f:
        f.write(verificacao_resultado + "\n")
        f.write(f"Mensagem Descriptografada:\n{mensagem_descriptografada}")
    print(f"Resultado da verificação salvo em: {ARQUIVO_RESULTADO_ASSINATURA}")
    print(f"\nResultado Final da Verificação: {verificacao_resultado}")

    print("\n--- Processo Concluído para Equipe B ---")

# --- Execução Principal ---
if __name__ == "__main__":
    # 1. Gerar (ou carregar) as próprias chaves da Equipe B
    # Isso garante que você tenha a chave privada para descriptografar.
    pubkey_b, privkey_b = gerar_chaves_b()

    # Se você já tem suas chaves geradas e apenas quer carregar, use a função abaixo
    # ao invés de gerar_chaves_b()
    # privkey_b, pubkey_a_carregada = carregar_chaves()
    # pubkey_a = pubkey_a_carregada # Renomeando para clareza

    # 2. Carregar as chaves necessárias (sua privada e a pública da Equipe A)
    privkey_b_loaded, pubkey_a = carregar_chaves()

    # 3. Descriptografar e verificar a assinatura
    descriptografar_e_verificar(privkey_b_loaded, pubkey_a)