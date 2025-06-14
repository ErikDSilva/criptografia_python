# gerar_chaves_a.py
import rsa

public_key, private_key = rsa.newkeys(2048)

with open('chaves/chave_publica_a.pem', 'wb') as pub:
    pub.write(public_key.save_pkcs1())

with open('chaves/chave_privada_a.pem', 'wb') as priv:
    priv.write(private_key.save_pkcs1())
