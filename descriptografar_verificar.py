import rsa
import base64

# Carregar chave privada da Equipe B
with open('chaves/chave_privada_b.pem', 'rb') as f:
    private_key_b = rsa.PrivateKey.load_pkcs1(f.read())

# Carregar chave pública da Equipe A
with open('chaves/chave_publica_a.pem', 'rb') as f:
    public_key_a = rsa.PublicKey.load_pkcs1(f.read())

# Carregar mensagem criptografada em base64
with open('mensagens/mensagem_cripto.txt', 'rb') as f:
    mensagem_cripto_base64 = f.read()
    mensagem_cripto = base64.b64decode(mensagem_cripto_base64)

# Descriptografar com a chave privada da Equipe B
mensagem = rsa.decrypt(mensagem_cripto, private_key_b)
with open('mensagens/mensagem_recebida.txt', 'wb') as f:
    f.write(mensagem)

# Verificar assinatura
with open('mensagens/assinatura.bin', 'rb') as f:
    assinatura = f.read()

try:
    rsa.verify(mensagem, assinatura, public_key_a)
    resultado = "Assinatura verificada com sucesso!"
except rsa.VerificationError:
    resultado = "Falha na verificação da assinatura."

with open('mensagens/assinatura_verificada.txt', 'w') as f:
    f.write(resultado)

print(resultado)
