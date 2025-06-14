# criptografar_assinar.py
import rsa

# Carregar chave pública da Equipe B
with open('chaves/chave_publica_b.pem', 'rb') as f:
    public_key_b = rsa.PublicKey.load_pkcs1(f.read())

# Carregar chave privada da Equipe A
with open('chaves/chave_privada_a.pem', 'rb') as f:
    private_key_a = rsa.PrivateKey.load_pkcs1(f.read())

# Mensagem original
mensagem = "Olá Equipe B, esta é uma mensagem secreta.".encode('utf-8')

with open('mensagens/mensagem.txt', 'wb') as f:
    f.write(mensagem)

# Criptografar com a chave pública da Equipe B
mensagem_cripto = rsa.encrypt(mensagem, public_key_b)
with open('mensagens/mensagem_cripto.txt', 'wb') as f:
    f.write(mensagem_cripto)

# Assinar com a chave privada da Equipe A
assinatura = rsa.sign(mensagem, private_key_a, 'SHA-256')
with open('mensagens/assinatura.bin', 'wb') as f:
    f.write(assinatura)
