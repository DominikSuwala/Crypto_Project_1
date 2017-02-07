# Crypto_Project_1

A project for a cryptography course at RIT.

## Project Specifications:

https://www.cs.rit.edu/~ark/spring2014/462/p1/p1.shtml

## Compile:

On Linux / OS X

> javac -classpath "pj2.jar:." *.java

On Windows

> javac -classpath "pj2.jar;." *.java

## Running:

{Encrypt/Decrypt} - Encrypts/Decrypts one 64-bit data block with ARK1 block cipher

On Linux / OS X

> java -classpath "pj2.jar:." {Encrypt, Decrypt} {HEX_128_BIT_KEY} {HEX_64_BIT_DATA}

On Windows

> java -classpath "pj2.jar;." {Encrypt, Decrypt} {HEX_128_BIT_KEY} {HEX_64_BIT_DATA}

{EncryptFile/DecryptFile} - Encrypt/Decrypt a file using ARK1 in ECB mode.

On Linux / OS X

> java -classpath "pj2.jar:." {EncryptFile, DecryptFile} {HEX_128_BIT_KEY} {INPUT_FILE} {OUTPUT_FILE}

On Windows

> java -classpath "pj2.jar;." {EncryptFile, DecryptFile} {HEX_128_BIT_KEY} {INPUT_FILE} {OUTPUT_FILE}
