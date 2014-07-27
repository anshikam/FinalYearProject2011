#include <iostream>
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/integer.h"
#include "cryptopp/sha.h"
#include "cryptopp/filters.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"

//check validation of keys , print keys

int main()
{
        CryptoPP::AutoSeededRandomPool rng;
        typedef CryptoPP::ECDH < CryptoPP::ECP >::Domain ECDHDomain;
        const CryptoPP::OID CURVE = CryptoPP::ASN1::secp160r1();

        //alice
        ECDHDomain alice = ECDHDomain( CURVE );
        byte alice_privKey[1024];
        byte alice_pubKey[1024];
        alice.GenerateKeyPair (rng, alice_privKey, alice_pubKey);

        //bob
        ECDHDomain bob = ECDHDomain( CURVE );
        byte bob_privKey[1024];
        byte bob_pubKey[1024];
        bob.GenerateKeyPair (rng, bob_privKey, bob_pubKey);

        byte bob_agreedValue[1024];
        byte alice_agreedValue[1024];

        // agree key material
        bob.Agree (bob_agreedValue, bob_privKey, alice_pubKey);
        alice.Agree (alice_agreedValue, alice_privKey, bob_pubKey);

        if ( (alice.AgreedValueLength() != bob.AgreedValueLength()) || (memcmp (bob_agreedValue, alice_agreedValue,alice.AgreedValueLength()) != 0) )
                std::cout<<"something wrong\n";
	else
		std::cout<<"ECDH --> key agreement algorithm verified successfully\n";

	return 0;
}


