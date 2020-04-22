# TP2

## Enunciado

Este trabalho é uma iniciação aos corpos finitos primos, às curvas elípticas sobre tais corpos  e aos esquemas criptográficos neles baseados (RSA , DSA e ECDSA) usando o SageMath.

1. Construir uma classe Python que implemente um esquema KEM- RSA-OAEP. A classe deve:

        1. Inicializar cada instância recebendo como parâmetro obrigatório o parâmetro de segurança (tamanho em bits do módulo RSA-OAEP) e gerando as chaves pública e privada.
        2. Conter funções para encapsulamento e revelação da chave gerada.
        3. Construir,  a partir deste KEM e usando a transformação de Fujisaki-Okamoto, um PKE que seja IND-CCA seguro.
2. Construir uma classe Python que implemente o DSA. A implementação deve:

        1. A iniciação,  receber como parâmetros o tamanho  dos primos p e q.
        2. Conter funções para assinar digitalmente e verificar a assinatura.
3. Construir uma classe Python que implemente o ECDSA usando uma das curvas elípticas primas definidas no FIPS186-4  (escolhida  na iniciação da classe).

## Explicação

Na questão 1 falta a implementação do **KEM** e do **Fujisaki-Okamoto** ou, pelo menos, parte dele.

Na questão 3 falta o processo de assinatura e geração de chaves.

## Exercício 1

[Exercício 1](https://github.com/Zayts3v/ec/blob/master/TP2/Ex1.ipynb)

## Exercício 2

Basta compilar o programa com ```python3 <ficheiro>```.

[Exercício 2](https://github.com/Zayts3v/ec/blob/master/TP2/Ex2.py)

## Exercício 3

[Exercício 3](https://github.com/Zayts3v/ec/blob/master/TP2/Ex3.ipynb)

## Relatório

[Relatório](https://github.com/Zayts3v/ec/blob/master/TP2/Relatório.pdf)
