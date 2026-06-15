#!/bin/bash

rm -f lisboa.txt porto.txt braga.txt

# Exercicio 1
echo "Lisboa" > lisboa.txt
echo "Porto" > porto.txt
echo "Braga" > braga.txt

# Exercicio 2
ls -l lisboa.txt

# Exercicio 3
chmod 666 lisboa.txt
ls -l lisboa.txt

# Exercicio 4
chmod 500 porto.txt
ls -l porto.txt

# Exercicio 5
chmod 400 braga.txt
ls -l braga.txt

# Exercicio 6
mkdir -p dir1 dir2
ls -ld dir1 dir2

# Exercicio 7
chmod go-x dir2
ls -ld dir2
