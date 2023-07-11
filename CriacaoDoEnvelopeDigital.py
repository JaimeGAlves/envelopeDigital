from base64 import b64encode
from Crypto.Cipher import AES, ARC4, DES, PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def envelope_creation(input_file_message_path, output_file_key, output_file_message, place_public_key_rec, algorithm_crypt,):
    
    if input_file_message_path != "":
        input_file_message = open(input_file_message_path, "rt")
    else:
        file_name = input("Digite o nome do arquivo de texto em claro: ")
        input_file_message_path = "remetente/" + file_name + ".txt"
        input_file_message = open(input_file_message_path, "w")
        input_message = input("Digite a mensagem em claro: ")
        input_file_message.write(input_message)
        input_file_message.close()

    input_file_message = open(input_file_message_path, "rt")
    plaintext = input_file_message.read().encode("utf-8")
    input_file_message.close()

    print(algorithm_crypt)
    
    if algorithm_crypt in ["aes", "AES"]:
        print("OK")
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipher_text = cipher_aes.encrypt(plaintext)
        output_file_message.write(b64encode(cipher_aes.nonce + cipher_text))
    
    if algorithm_crypt in ["des", "DES"]:
        session_key = get_random_bytes(8)
        cipher_des = DES.new(session_key, DES.MODE_EAX)
        cipher_text = cipher_des.encrypt(plaintext)
        output_file_message.write(b64encode(cipher_des.nonce + cipher_text))
    
    if algorithm_crypt in ["rc4" or "RC4"]:
        session_key = get_random_bytes(16)
        nonce_rc4 = get_random_bytes(16)
        tempkey = SHA.new(session_key + nonce_rc4).digest()
        cipher_rc4 = ARC4.new(tempkey)
        cipher_text = cipher_rc4.encrypt(plaintext)
        output_file_message.write(b64encode(nonce_rc4 + cipher_text))
    
    chave_publica_receptor = RSA.import_key(open(place_public_key_rec).read())
    cipher_rsa = PKCS1_OAEP.new(chave_publica_receptor)
    enc_session_key = cipher_rsa.encrypt(session_key)
    output_file_key.write(b64encode(enc_session_key))
    output_file_message.close()
    output_file_key.close()

    print("A mensagem foi criptografada com sucesso.")

print("Digite os caminhos solicitados, caso queira usar os caminhos padrões, basta pressionar Enter sem digitar nada")

print("Digite o caminho do texto em claro: ")
input_file_message_path = input()

print("Digite o caminho da chave pública do receptor: ")
input_file_public_key_rec_path = input()

print("Escolha o algoritmo de criptografia da mensagem (aes, des ou rc4):")
algorithm_crypt = input()

while (
    algorithm_crypt != "aes"
    and algorithm_crypt != "AES"
    and algorithm_crypt != "des"
    and algorithm_crypt != "DES"
    and algorithm_crypt != "RC4"
    and algorithm_crypt != "rc4"
):
    print("Por favor, digite uma entrada válida (aes, des ou rc4):")
    algorithm_crypt = input()

output_file_key = open("receptor/chave_encriptada.base64", "wb")
output_file_message = open("receptor/mensagem_encriptada.base64", "wb")

envelope_creation(
    input_file_message_path,
    output_file_key,
    output_file_message,
    input_file_public_key_rec_path,
    algorithm_crypt,
)