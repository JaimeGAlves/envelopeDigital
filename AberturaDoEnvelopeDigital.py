from base64 import b64decode
from Crypto.Cipher import AES, ARC4, DES, PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA

def open_envelope(input_file_message, input_file_enc_key, place_private_key_rec, place_dec_message, algorithm_crypt):
    chave_privada_receptor = RSA.import_key(open(place_private_key_rec).read())
    enc_session_key = b64decode(input_file_enc_key.read())
    cipher_rsa = PKCS1_OAEP.new(chave_privada_receptor)
    session_key = cipher_rsa.decrypt(enc_session_key)

    if algorithm_crypt in ["aes", "AES"]:
        nonce_aes_tag_cipher_text = b64decode(input_file_message.read())
        nonce_aes = nonce_aes_tag_cipher_text[:16]
        cipher_text = nonce_aes_tag_cipher_text[16:]
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce_aes)
        plaintext = cipher_aes.decrypt(cipher_text)
        
    if algorithm_crypt in ["des", "DES"]:
        nonce_des_ciphertext = b64decode(input_file_message.read())
        nonce_des = nonce_des_ciphertext[0:16]
        cipher_text = nonce_des_ciphertext[16:]
        cipher_des = DES.new(session_key, DES.MODE_EAX, nonce_des)
        plaintext = cipher_des.decrypt(cipher_text)
        
    if algorithm_crypt in ["rc4", "RC4"]:
        nonce_rc4_cipher_text = b64decode(input_file_message.read())
        nonce_rc4 = nonce_rc4_cipher_text[0:16]
        cipher_text = nonce_rc4_cipher_text[16:]
        tempkey = SHA.new(session_key + nonce_rc4).digest()
        cipher_rc4 = ARC4.new(tempkey)
        plaintext = cipher_rc4.decrypt(cipher_text)
        
    file_out_message = open(place_dec_message, "wt")
    file_out_message.write(plaintext.decode())
    print(plaintext.decode())
    file_out_message.close()
    input_file_message.close()
    input_file_enc_key.close()

print(
    "Digite o caminho solicitado, caso queira usar os caminhos padrões, basta pressionar Enter sem digitar nada"
)

print("Digite o caminho onde está a mensagem encriptada: ")
input_file_enc_message = input()
print("Digite o caminho da chave encriptada: ")
input_file_enc_key = input()
print("Digite o caminho onde está a chave privada do receptor: ")
input_file_private_key = input()
print("Escolha o algoritmo utilizado na criptografia da mensagem:")
algorithm_crypt = input()
while (
    algorithm_crypt != "aes"
    and algorithm_crypt != "AES"
    and algorithm_crypt != "des"
    and algorithm_crypt != "DES"
    and algorithm_crypt != "RC4"
    and algorithm_crypt != "rc4"
):
    print("Por favor digite uma entrada válida:")
    algorithm_crypt = input()

if input_file_enc_message != "":
    input_file_enc_message = open(input_file_enc_message, "rb")
else:
    input_file_enc_message = open("receptor/mensagem_encriptada.base64", "rb")

if input_file_enc_key != "":
    input_file_enc_key = open(input_file_enc_key, "rb")
else:
    input_file_enc_key = open("receptor/chave_encriptada.base64", "rb")

if input_file_private_key == "":
    input_file_private_key = "receptor/chave_privada_receptor.pem"

output_file_dec_message = "receptor/mensagem_encriptada.base64"

open_envelope(
    input_file_enc_message,
    input_file_enc_key,
    input_file_private_key,
    output_file_dec_message,
    algorithm_crypt,
)