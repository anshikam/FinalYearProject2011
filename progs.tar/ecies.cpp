// Crypto++ Includes
#include<iostream>
using namespace std;
#include<fstream>
#include "cryptopp/cryptlib.h"
#include "cryptopp/oids.h"
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/asn.h"
#include "cryptopp/ecp.h"
#include "cryptopp/ec2n.h"
#include "cryptopp/simple.h"

#define ECC_ALGORITHM CryptoPP::ECP
#define ECC_CURVE CryptoPP::ASN1::secp160r1()
  
int main (int argc, char *argv[])
{
       
        CryptoPP::ECIES < ECC_ALGORITHM >::PrivateKey privateKey;    
        CryptoPP::ECIES < ECC_ALGORITHM >::PublicKey publicKey;    
        CryptoPP::AutoSeededRandomPool rng;    
	
        // Generate private key    
	bool result=false;
	privateKey.Initialize( rng, CryptoPP::ASN1::secp160r1());
	assert( privateKey.Validate( rng, 3 ) );
	result=privateKey.Validate( rng, 3 );
	assert( true == result );
	if( !result ) { return -1; }

	//generate public key
	result=false;
	privateKey.MakePublicKey(publicKey);
	assert( publicKey.Validate( rng, 3 ) );
	result=publicKey.Validate( rng, 3 );
	assert( true == result );
	if( !result ) { return -2; }
	      
        // Encryptor and Decryptor
        CryptoPP::ECIES < ECC_ALGORITHM >::Encryptor Encryptor (publicKey);    
        CryptoPP::ECIES < ECC_ALGORITHM >::Decryptor Decryptor (privateKey);
    
        // Message
	fstream inFile,opFile;
	inFile.open("myfile.txt",ios ::in | ios ::binary);
	opFile.open("cipher.txt",ios ::out | ios ::binary);
	while(!inFile.eof())
 	{
		char s;
        	char str[129]={0};
		int i=0;

		//reading plaintext from file
		while(i<128)
		{
  			inFile.read((char *)&s,sizeof(char));
  			str[i++]=s;
		}
		str[i]='\0';
		string plainText(str);
		size_t plainTextLength = plainText.length () + 1;

	        cout << "\n*************************************************\nPLAIN TEXT: \n" << plainText << endl;
	        cout << "PLAIN TEXT LENGTH IS: " << plainTextLength << " (including the trailing NULL)" << endl;

	        // Size  
	        size_t cipherTextLength = Encryptor.CiphertextLength (plainTextLength);
    
       	     
        	cout << "CIPHER TEXT LENGTH IS: ";
        	cout << cipherTextLength << endl;

        	// Encryption buffer
        	byte * cipherText = new byte[cipherTextLength];
        
        	memset (cipherText, 0xFB, cipherTextLength);

        	// Encryption
        	Encryptor.Encrypt (rng, reinterpret_cast < const byte * > (plainText.data ()), plainTextLength, cipherText); 
		
		//writing ciphertext to file
		cout<<"\n------------------------------\n"<<cipherText<<"\n------------------------------\n";
		i=0;
		while(i<cipherTextLength)
		{
			opFile.write((char*)&cipherText[i++],sizeof(byte));
		} 	

        	// Size
        	size_t recoveredTextLength = Decryptor.MaxPlaintextLength (cipherTextLength);    
        

        	// Decryption Buffer
        	char * recoveredText = new char[recoveredTextLength];
        
        	memset (recoveredText, 0xFB, recoveredTextLength);
    
        	// Decryption
        	Decryptor.Decrypt (rng, cipherText, cipherTextLength, reinterpret_cast < byte * >(recoveredText));     

        	cout << "RECOVERED TEXT :\n" << recoveredText << endl;
		cout << "RECOVERED TEXT LENGTH IS: " << recoveredTextLength << endl;
	        
		// Cleanup
	        if (NULL != cipherText)
	        {        
	            delete[] cipherText;      
	        }

	        if (NULL != recoveredText)
	        {        
	            delete[] recoveredText;      
	        }
    

 	}
	inFile.close();
	opFile.close();
        
    return 0;
}

