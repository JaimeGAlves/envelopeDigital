from Crypto.PublicKey import RSA

key_alice = RSA.generate(2048)

private_key_alice = key_alice.export_key()
file_out = open("remetente/chave_privada_remetente.pem", "wb")
file_out.write(private_key_alice)
file_out.close()

chave_publica_remetente = key_alice.publickey().export_key()
file_out = open("receptor/chave_publica_remetente.pem", "wb")
file_out.write(chave_publica_remetente)
file_out.close()

key_bob = RSA.generate(2048)

chave_privada_receptor = key_bob.export_key()
file_out = open("receptor/chave_privada_receptor.pem", "wb")
file_out.write(chave_privada_receptor)
file_out.close()

chave_publica_receptor = key_bob.publickey().export_key()
file_out = open("remetente/chave_publica_receptor.pem", "wb")
file_out.write(chave_publica_receptor)
file_out.close()

print("As chaves foram criadas com sucesso e estão nas devidas pastas.")