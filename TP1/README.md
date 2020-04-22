# TP1

## Enunciado

1. Construir uma sessão síncrona de comunicação segura entre dois agentes (o Emitter e o Receiver), combinando os seguintes elementos constituintes
    1. um gerador de nounces: um nounce, que nunca foi usado antes, deve ser criado aleatoriamente em cada instância da comunicação.
    2. a cifra simétrica AES usando autenticação de cada criptograma com HMAC e um modo seguro contra ataques aos vectores de iniciação (iv's).
    3. o protocolo de acordo de chaves Diffie-Hellman com verificação da chave, e  autenticação dos agentes através do esquema de assinaturas DSA.
2. Usando Curvas Elípticas, criar uma versão do esquema anterior substituindo, 
    1. A cifra simétrica por ChaCha20Poly1305
    2. no protocolo de acordo de chaves, o DH  pelo ECDH e o DSA pelo ECDSA.

## Explicação

Ambos os exercícios foram feitos em *Python*, ao invés de *Jupyter Notebook*. Os exercícios resolvidos encontra-se nas respetivas diretorias. Enquanto que os ficheiros do Jupyter, que foram começados mas o grupo sentiu bastantes dificuldades em resolver os problemas, estão anexados na pasta principal.

## Exercício 1

Basta compilar os programas com ```python3 <ficheiro>``` (Primeiro, o **Receiver**).

[Emitter](https://github.com/Zayts3v/ec/blob/master/TP1/Exercicio1/Emitter.py)
[Receiver](https://github.com/Zayts3v/ec/blob/master/TP1/Exercicio1/Receiver.py)

## Exercício 2

Basta compilar os programas com ```python3 <ficheiro>``` (Primeiro, o **Receiver**).

[Emitter](https://github.com/Zayts3v/ec/blob/master/TP1/Exercicio2/Emitter.py)
[Receiver](https://github.com/Zayts3v/ec/blob/master/TP1/Exercicio2/Receiver.py)

## Relatório

[Relatório](https://github.com/Zayts3v/ec/blob/master/TP1/Relatório.pdf)
