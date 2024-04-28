#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
gcc -g -DTEST -o hello_world hello_world.c

./hello_world
Hello World!

./hello_world test
Hello World!
Arg2: "test"

./hello_world
...
Loop 9

./hello_world 10

 */

#define HELPER(n) printf("Arg 2: \"%s\"\n", n);

#ifdef TEST
#endif

void do_work(const char* str)
{
    printf("str %s\n", str);
}
#define LOOP_SZ 10
int main(int argc, char* argv[])
{
    char* arg2 = NULL;
    int val;
    unsigned int ar[LOOP_SZ];
    const char* str = "my string";

    memset(ar, 0, sizeof(ar));

    printf("Hello World!\n");

    if (argc >= 2) {
        arg2 = argv[1];
        HELPER(arg2);

        val = atoi(arg2);
        
    }

    for (int i=0; i<LOOP_SZ; i++) {
        ar[i] = i;
        printf("Loop %d\n", ar[i]);
    }

    do_work("some string");

    switch (val) {
        case 1:
            printf("I used 1\n");
            break;
        case 2:
            printf("I used 2\n");
            break;
        default:
            printf("Invalid\n");
            break;
    }

    return 0;
}


/*
Asymmetric
Private key / public key
ECC (Elipical Curve Cryptography)
RSA 2048-bit (256 bytes) modulus exponent 
ED25519 / Curve 25119
DH

Symmetric
Ciphers
AES (ECB, CBC, CTR, GCM, CCM) 128/192/256 bit keys
ChaCha20
DES3

Hash/Digest
SHA2-256
SHA3

X.509 Certifcates -> ASN.1

*/