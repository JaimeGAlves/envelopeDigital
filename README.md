# Projeto disponível no GitHub:
    https://github.com/JaimeGAlves/envelopeDigital


# Grupo:
    Jaime Gabriel Alves Pereira
    Cláudio Matheus da Silva Sousa
    Francisco de Assis Machado dos Santos


# Passo-a-Passo para rodar o projeto:
    1. Instalar o Python
    2. Instalar as dependências
    3. Rodar o projeto
## 1. Instalar o Python
    Faça o download do Python 3.11.4 no site oficial: https://www.python.org/downloads/

## 2. Instalar as dependências
    Abra o terminal e digite o comando: pip install -r requirements.txt

## 3. Rodar o projeto
    1. Abra o terminal e digite o comando: python CriacaoDeChavesAssimetricas.py
    2. Abra o terminal e digite o comando: python CriacaoDoEnvelopeDigital.py
        - Digite o caminho do texto em claro (apenas dar enter criará o arquivo no caminho padrão)
        - Digite o caminho da chave pública do receptor (CriacaoDeChavesAssimetricas.py criará a chave pública do receptor em remetente/chave_publica_receptor.pem)
        - Escolha qual algoritmo de criptografia utilizar (AES, DES ou RC4)
        - Digite o nome do arquivo do texto em claro
        - Digite a mensagem a ser criptografada
    3. Abra o terminal e digite o comando: python AberturaDoEnvelopeDigital.py
        - Digite o caminho onde está a mensagem criptografada (CriacaoDoEnvelopeDigital.py criará a mensagem criptografada por padrão em remetente/<nome-que-voce-escolher>.txt)
        - Digite o caminho da chave encriptada (apenas dar enter pegará a chave encriptada no caminho padrão)
        - Digite o caminho da chave privada do receptor (apenas dar enter pegará a chave privada do receptor no caminho padrão)
        - Escolha o algoritmo de criptografia utilizado na criação do envelope (AES, DES ou RC4)