#include <stdio.h>
#include <assert.h>
#include <iostream>
#include <fstream>
using namespace std;

#include <string>
using std::string;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;

#include "cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;

#include "cryptopp/oids.h"
using CryptoPP::OID;

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key );
void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key );
void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params );

//////////////////////////////////////////
// In 2010, use SHA-256 and P-256 curve
//////////////////////////////////////////

int main(int argc, char* argv[])
{
    // Private and Public keys
    ECDSA<ECP, SHA1>::PrivateKey privateKey;
    ECDSA<ECP, SHA1>::PublicKey publicKey;
    

    AutoSeededRandomPool prng;
    bool result = false;   
    
    // Generate private key    
    privateKey.Initialize( prng, CryptoPP::ASN1::secp160r1());
    assert( privateKey.Validate( prng, 3 ) );
    result=privateKey.Validate( prng, 3 );
    assert( true == result );
    if( !result ) { return -1; }

    //generate public key
    result=false;
    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );
    result=publicKey.Validate( prng, 3 );
    assert( true == result );
    if( !result ) { return -2; }
    
    // Print Domain Parameters   
    PrintDomainParameters( publicKey );
    
    //print private key
    cout << endl;
    cout << "Private Exponent:" << endl;
    cout << " " << privateKey.GetPrivateExponent() << endl; 
    
    //print public key
    cout << endl;
    cout << "Public Element:" << endl;
    cout << " X: " << publicKey.GetPublicElement().x << endl; 
    cout << " Y: " << publicKey.GetPublicElement().y << endl;
    
    // Sign and Verify a message      
    fstream inFile,opFile;
    inFile.open("myfile.txt",ios ::in | ios ::binary);
    opFile.open("signature.txt",ios ::out | ios ::binary);
    while(!inFile.eof())
    {
	char s;
        char str[129];
	int i=0;
	while(i<128)
	{
  		inFile.read((char *)&s,sizeof(char));
  		str[i++]=s;
	}
	str[i]='\0';
	string message(str);

	//signing	
	bool signResult=false;
	string signature;
        signature.erase();    
	StringSource( message, true,new SignerFilter( prng,ECDSA<ECP,SHA1>::Signer(privateKey),new StringSink( signature )) ); // StringSource
       	signResult=!signature.empty();

        assert( true == signResult );
        if(true==signResult)
        {    
        	cout<<"\n******************************\nMessage signed successfully\n";
    	} 

	//writing signed message to file
	cout<<"\n------------------------------\n"<<signature<<"\n------------------------------\n";
	const char *sign=signature.data();
	i=0;
	while(i<signature.length())
	{
		opFile.write((char*)&sign[i++],sizeof(char));
	}

	//verify signature
    	bool verifyResult = false;
	StringSource( signature+message, true,new SignatureVerificationFilter(ECDSA<ECP,SHA1>::Verifier(publicKey),new ArraySink( (byte*)&verifyResult, sizeof(verifyResult) ))     );    
        assert( true == verifyResult );
        if(true==verifyResult)
        {    
    		cout<<"Digital signature verified successfully\n";
        } 

    }
    inFile.close();
    opFile.close();
    return 0;
}


void PrintDomainParameters( const ECDSA<ECP, SHA1>::PrivateKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const ECDSA<ECP, SHA1>::PublicKey& key )
{
    PrintDomainParameters( key.GetGroupParameters() );
}

void PrintDomainParameters( const DL_GroupParameters_EC<ECP>& params )
{
    cout << endl;
 
    cout << "Modulus:" << endl;
    cout << " " << params.GetCurve().GetField().GetModulus() << endl;
    
    cout << "Coefficient A:" << endl;
    cout << " " << params.GetCurve().GetA() << endl;
    
    cout << "Coefficient B:" << endl;
    cout << " " << params.GetCurve().GetB() << endl;
    
    cout << "Base Point:" << endl;
    cout << " X: " << params.GetSubgroupGenerator().x << endl; 
    cout << " Y: " << params.GetSubgroupGenerator().y << endl;
    
    cout << "Subgroup Order:" << endl;
    cout << " " << params.GetSubgroupOrder() << endl;
    
    cout << "Cofactor:" << endl;
    cout << " " << params.GetCofactor() << endl;    
}



