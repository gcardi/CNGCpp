#pragma hdrstop
#pragma argsused

#ifdef _WIN32
#include <tchar.h>
#else
  typedef char _TCHAR;
  #define _tmain main
#endif

#include <System.SysUtils.hpp>

#include <vector>
#include <iterator>
#include <memory>
#include <algorithm>

#include <windows.h>
#include <stdio.h>
#include <conio.h>

#include <bcrypt.h>

//#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#pragma comment( lib, "bcrypt" )

#define USE_STD_VECTORS 

#if defined( USE_STD_VECTORS )
std::vector<BYTE> const rgbPlaintext {
    0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00, 0x34, 0x00, 0x35, 0x00, 
    0x36, 0x00, 0x37, 0x00, 0x38, 0x00, 0x39, 0x00, 0x61, 0x00, 0x42, 0x00, 
    0x63, 0x00, 0x44, 0x00, 0x65, 0x00,    
};
#else
TBytes rgbPlaintext =
    TEncoding::Unicode->GetBytes(
        _D( "" )
        "0123456789aBcDe"
    );
#endif

#if defined( USE_STD_VECTORS )
std::vector<BYTE> const rgbIV {
#else
TBytes rgbIV {
#endif
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
};

String SecretKey = _D( "sopralapancalacapracampasottolapancalacapracrepa" );

void Check( NTSTATUS ntStatus )
{
    if ( ntStatus < 0 ) {
        throw Exception(
            _D( "CNGCrypt Error 0x%08x" ),
            ARRAYOFCONST( ( ntStatus ) )
        );
    }
}

template<class T>
//using pippo = const_cast<typename std::iterator_traits<T>::value_type*>;
//using pippo = T*;
using pippo = typename std::iterator_traits<T>::value_type*;

template<typename I>
auto ItemNonConstAddrFromIt( I It ) {
    return const_cast<typename std::iterator_traits<I>::value_type*>(  &*It );
}

class AlgProvSessionMngr {
public:
    AlgProvSessionMngr( LPCWSTR Algo ) {
        Check( ::BCryptOpenAlgorithmProvider( &alg_, Algo, nullptr, 0 ) );
    }
    ~AlgProvSessionMngr() { ::BCryptCloseAlgorithmProvider( alg_, 0 ); }
    AlgProvSessionMngr( AlgProvSessionMngr&& ) = delete;
    AlgProvSessionMngr& operator=( AlgProvSessionMngr&& ) = delete;
    BCRYPT_ALG_HANDLE GetHndlr() const noexcept { return alg_; }

    template<typename K, typename PTI, typename IVI>
    DWORD GetEncryptOutputBufferSize( K& Key, PTI PlainTextBegin, PTI PlainTextEnd,
                                      IVI InitVectBegin, IVI InitVectEnd ) const
    {
        DWORD cbCipherText {};
        Check(
            ::BCryptEncrypt(
                Key.GetHndlr(),
                /*
                const_cast<typename std::iterator_traits<PTI>::value_type*>( 
                    &*PlainTextBegin 
                ),
                */
                ItemNonConstAddrFromIt( PlainTextBegin ),
                std::distance( PlainTextBegin, PlainTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( 
                    &*InitVectBegin 
                ),
                std::distance( InitVectBegin, InitVectEnd ),
                nullptr,
                {},
                &cbCipherText,
                BCRYPT_BLOCK_PADDING
            )
        );
        return cbCipherText;
    }

    template<typename K, typename CTI, typename IVI>
    DWORD GetDecryptOutputBufferSize( K& Key,
                                      CTI CipherTextBegin, CTI CipherTextEnd,
                                      IVI InitVectBegin, IVI InitVectEnd ) const
    {
        DWORD BlockLength {};
        Check(
            ::BCryptDecrypt(
                Key.GetHndlr(),
                const_cast<typename std::iterator_traits<CTI>::value_type*>( 
                    &*CipherTextBegin 
                ),
                std::distance( CipherTextBegin, CipherTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( 
                    &*InitVectBegin 
                ),
                std::distance( InitVectBegin, InitVectEnd ),
                nullptr,
                {},
                &BlockLength,
                BCRYPT_BLOCK_PADDING
            )
        );
        return BlockLength;
    }

    DWORD GetObjectLength() const {
        DWORD Dummy {};
        DWORD Object {};
        Check(
            ::BCryptGetProperty(
                alg_, BCRYPT_OBJECT_LENGTH, (PBYTE)&Object,
                sizeof Object, &Dummy, {}
            )
        );
        return Object;
    }

private:
    BCRYPT_ALG_HANDLE alg_ {};

};
//---------------------------------------------------------------------------

class CipherProvSessionMngr : public AlgProvSessionMngr {
public:
    template<typename...A>
    CipherProvSessionMngr( A&&... Args )
      : AlgProvSessionMngr{ std::forward<A>( Args )... } {}

    template<typename K, typename PTI, typename IVI>
    std::vector<BYTE> Encrypt( K& Key, PTI PlainTextBegin, PTI PlainTextEnd,
                               IVI InitVectBegin, IVI InitVectEnd )
    {
        std::vector<BYTE> IV( InitVectBegin, InitVectEnd );

        std::vector<BYTE> CipherText(
            GetEncryptOutputBufferSize(
                Key,
                PlainTextBegin, PlainTextEnd,
                std::begin( IV ), std::end( IV )
            )
        );
        auto const Size = Encrypt(
            Key, PlainTextBegin, PlainTextEnd,
            std::begin( CipherText ), std::end( CipherText ),
            std::begin( IV ), std::end( IV )
        );
        CipherText.resize( Size );
        return CipherText;
    }

    template<typename K, typename CTI, typename IVI>
    std::vector<BYTE> Decrypt( K& Key, CTI CipherTextBegin, CTI CipherTextEnd,
                               IVI InitVectBegin, IVI InitVectEnd )
    {
        std::vector<BYTE> IV( InitVectBegin, InitVectEnd );

        std::vector<BYTE> PlainText(
            GetDecryptOutputBufferSize(
                Key,
                CipherTextBegin, CipherTextEnd,
                std::begin( IV ), std::end( IV )
            )
        );

//        wprintf( L"\nDecr Blk Len: %d\n\n", PlainText.size() );

        auto const Size = Decrypt(
            Key, CipherTextBegin, CipherTextEnd,
            std::begin( PlainText ), std::end( PlainText ),
            std::begin( IV ), std::end( IV )
        );
        PlainText.resize( Size );
        return PlainText;
    }
private:
    template<typename IVI>
    void CheckBlockLength( IVI InitVectBegin, IVI InitVectEnd ) const
    {
        // Calculate the block length for the IV.
        auto const IVBlockLength = GetBlockLength();

        // Determine whether the cbBlockLen is not longer than the IV length.
        if ( IVBlockLength > std::distance( InitVectBegin, InitVectEnd ) ) {
            throw Exception(
                _D( "**** block length is longer than the provided IV length\n")
            );
        }
    }

    DWORD GetBlockLength() const noexcept {
        DWORD Dummy {};
        DWORD BlockLen {};
        Check(
            ::BCryptGetProperty(
                GetHndlr(),
                BCRYPT_BLOCK_LENGTH,
                (PBYTE)&BlockLen,
                sizeof BlockLen,
                &Dummy,
                {}
            )
        );
        return BlockLen;
    }

    template<typename K, typename PTI, typename CTI, typename IVI>
    DWORD Encrypt( K& Key, PTI PlainTextBegin, PTI PlainTextEnd,
                   CTI CipherTextBegin, CTI CipherTextEnd,
                   IVI InitVectBegin, IVI InitVectEnd )
    {
        CheckBlockLength( InitVectBegin, InitVectEnd );

        DWORD BlockLen {};

        Check(
            ::BCryptEncrypt(
                Key.GetHndlr(),
                const_cast<typename std::iterator_traits<PTI>::value_type*>( &*PlainTextBegin ),
                std::distance( PlainTextBegin, PlainTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( &*InitVectBegin ),
                std::distance( InitVectBegin, InitVectEnd ),
                const_cast<typename std::iterator_traits<CTI>::value_type*>( &*CipherTextBegin ),
                std::distance( CipherTextBegin, CipherTextEnd ),
                &BlockLen,
                BCRYPT_BLOCK_PADDING
            )
        );

//        wprintf( L"\n(Priv) Encr Blk Len: %d\n\n", BlockLen );
        
        return BlockLen;
    }

    template<typename K, typename PTI, typename CTI, typename IVI>
    DWORD Decrypt( K& Key, CTI CipherTextBegin, CTI CipherTextEnd,
                   PTI PlainTextBegin, PTI PlainTextEnd,
                   IVI InitVectBegin, IVI InitVectEnd )
    {
        CheckBlockLength( InitVectBegin, InitVectEnd );

        DWORD BlockLen {};

        Check(
            ::BCryptDecrypt(
                Key.GetHndlr(),
                const_cast<typename std::iterator_traits<CTI>::value_type*>( &*CipherTextBegin ),
                std::distance( CipherTextBegin, CipherTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( &*InitVectBegin ),
                std::distance( InitVectBegin, InitVectEnd ),
                &*PlainTextBegin,
                std::distance( PlainTextBegin, PlainTextEnd ),
                &BlockLen,
                BCRYPT_BLOCK_PADDING
            )
        );

        return BlockLen;
    }

};
//---------------------------------------------------------------------------

class AESAlgProvSessionMngr : public CipherProvSessionMngr {
public:
    AESAlgProvSessionMngr() : CipherProvSessionMngr{ BCRYPT_AES_ALGORITHM } {}
};
//---------------------------------------------------------------------------

class AESCBCAlgProvSessionMngr : public AESAlgProvSessionMngr {
public:
    AESCBCAlgProvSessionMngr()
    {
        Check(
            ::BCryptSetProperty(
                GetHndlr(), BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                sizeof(BCRYPT_CHAIN_MODE_CBC), {}
            )
        );
    }
};

//---------------------------------------------------------------------------

class SimmetricKeyMngr {
public:
    template<typename A>
    SimmetricKeyMngr( A& Alg ) : keyObject_( Alg.GetObjectLength() ) {}

    template<typename A, typename KI>
    SimmetricKeyMngr( A& Alg, KI KeyBegin, KI KeyEnd ) 
      : SimmetricKeyMngr( Alg )
    {
        Generate( Alg, KeyBegin, KeyEnd );
    }

    template<typename A, typename KI>
    void Generate( A& Alg, KI KeyBegin, KI KeyEnd )
    {
        Check(
            ::BCryptGenerateSymmetricKey(
                Alg.GetHndlr(), &key_, keyObject_.data(), keyObject_.size(),
                const_cast<typename std::iterator_traits<KI>::value_type*>( &*KeyBegin ),
                std::distance( KeyBegin, KeyEnd ), {}
            )
        );
    }

    template<typename A, typename BI>
    void Import( A& Alg, BI BlobBegin, BI BlobEnd )
    {
        Check(
            ::BCryptImportKey(
                Alg.GetHndlr(), nullptr, BCRYPT_OPAQUE_KEY_BLOB, &key_,
                keyObject_.data(), keyObject_.size(),
                const_cast<typename std::iterator_traits<BI>::value_type*>( 
                    &*BlobBegin 
                ),
                std::distance( BlobBegin, BlobEnd ),
                {}
            )
        );
    }

    std::vector<BYTE> Export() const {
        DWORD cbBlob {};

        Check(
            ::BCryptExportKey(
                key_, nullptr, BCRYPT_OPAQUE_KEY_BLOB, nullptr, {}, &cbBlob, {}
            )
        );

        std::vector<BYTE> Ret( cbBlob );

        Check(
            ::BCryptExportKey(
                key_, nullptr, BCRYPT_OPAQUE_KEY_BLOB, Ret.data(), Ret.size(),
                &cbBlob, {}
            )
        );

        return Ret;
    }

    void ClearKeyObject() noexcept {
        std::fill( std::begin( keyObject_ ), std::end( keyObject_ ), 0 );
    }

    ~SimmetricKeyMngr() { if ( key_ ) { ::BCryptDestroyKey( key_ ); } }
    SimmetricKeyMngr( SimmetricKeyMngr&& ) = delete;
    SimmetricKeyMngr& operator=( SimmetricKeyMngr&& ) = delete;
    BCRYPT_KEY_HANDLE GetHndlr() const noexcept { return key_; }
private:
    BCRYPT_KEY_HANDLE key_ {};
    std::vector<BYTE> keyObject_;
};
//---------------------------------------------------------------------------

class SHA256AlgProvSessionMngr : public AlgProvSessionMngr {
public:
    SHA256AlgProvSessionMngr() 
      : AlgProvSessionMngr{ BCRYPT_SHA256_ALGORITHM } 
      , obj_( GetObjectLength() )
    {
        Check(
            ::BCryptCreateHash(
                GetHndlr(), &hHash_, &obj_[0], obj_.size(), nullptr, {}, {}
            )
        );
    }

    ~SHA256AlgProvSessionMngr() { ::BCryptDestroyHash( hHash_ ); }

    template<typename DI>
    std::vector<byte> Process( DI DataBegin, DI DataEnd )
    {
	    Check(
            ::BCryptHashData(
                hHash_, &*DataBegin, std::distance( DataBegin, DataEnd ), {}
            )
        );

        DWORD HashLen {};
        DWORD Dummy {};
        Check(
            ::BCryptGetProperty(
                GetHndlr(), BCRYPT_HASH_LENGTH, 
                (PBYTE)&HashLen, sizeof HashLen,
                &Dummy, 0
            )
        );

        std::vector<BYTE> Hash( HashLen );

	    Check( ::BCryptFinishHash( hHash_, Hash.data(), Hash.size(), {} )  );

        return Hash;
    }
private:
    std::vector<BYTE> obj_;
    BCRYPT_HASH_HANDLE hHash_ {};

};
//---------------------------------------------------------------------------

template<typename B>
String BytesToHex( B&& Bytes )
{
    auto SB = std::make_unique<TStringBuilder>();
    for ( auto b : Bytes ) {
        SB->AppendFormat( _T( "%.2X" ), ARRAYOFCONST(( b )) );
    }
    return SB->ToString();
}

template<typename B, typename S>
String BytesToHex( B&& Bytes, S&& Sep )
{
    auto SB = std::make_unique<TStringBuilder>();

    auto b = std::begin( Bytes );
    auto e = std::end( Bytes );
    if ( b != e ) {
        SB->AppendFormat( _T( "%.2X" ), ARRAYOFCONST(( *b )) );
        while ( ++b != e ) {
            SB->AppendFormat( _T( "%s%.2X" ), ARRAYOFCONST(( Sep, *b )) ) ;
        }
    }
    return SB->ToString();
}
//---------------------------------------------------------------------------

int _tmain(int argc, _TCHAR* argv[])
{
    try {
        wprintf( L"IV: %s\n", BytesToHex( rgbIV ).c_str() );

        SHA256AlgProvSessionMngr HashAlg;

        wprintf( L"Secret key: %s\n", SecretKey.c_str() );

        auto EncodedSecretKey = TEncoding::Unicode->GetBytes( SecretKey );

        auto const Hash = HashAlg.Process( 
            std::begin( EncodedSecretKey ), std::end( EncodedSecretKey ) 
        );

        auto HashStr = BytesToHex( Hash );

        wprintf( L"Sec key hash: %s\n", HashStr.c_str() );

        // Open an algorithm (AES CBC)
        AESCBCAlgProvSessionMngr Alg;

        // Create a simmetric key
        auto Key = std::make_unique<SimmetricKeyMngr>(
            Alg, std::begin( Hash ), std::end( Hash )
        );

        auto const Blob = Key->Export();

        wprintf( L"Text to cipher: %s\n", &rgbPlaintext[0] );
        wprintf( L"Text to cipher: %s\n", BytesToHex( rgbPlaintext ).c_str() );
        wprintf( 
            L"Text len: %d\n", 
            std::distance( std::begin( rgbPlaintext ), std::end( rgbPlaintext ) )
        );

        auto CipherText =
            Alg.Encrypt(
                *Key, std::begin( rgbPlaintext ), std::end( rgbPlaintext ),
                std::begin( rgbIV ), std::end( rgbIV )
            );

        wprintf( L"Cipher text: %s\n", &CipherText[0] );
        wprintf( L"Cipher text: %s\n", BytesToHex( CipherText ).c_str() );
        wprintf( L"Cipher text len: %d\n", CipherText.size() );

        // Destroy the old key and create a new one
        Key = std::move( std::make_unique<SimmetricKeyMngr>( Alg ) );

        // Import the key from saved blob
        Key->Import( Alg, std::begin( Blob ), std::end( Blob ) );

        // Decrypt ciphered text
        auto PlainText =
            Alg.Decrypt(
                *Key, std::begin( CipherText ), std::end( CipherText ),
                std::begin( rgbIV ), std::end( rgbIV )
            );

        wprintf( L"Returned Plain text: %s\n", &PlainText[0] );
        wprintf( L"Returned Plain text: %s\n", BytesToHex( PlainText ).c_str() );
        wprintf( L"Returned Plain text len: %d\n", PlainText.size() );

        // Compare with the original text
        auto Result =
            std::mismatch(
                std::begin( PlainText ), std::end( PlainText ),
                std::begin( rgbPlaintext ), std::end( rgbPlaintext )
            );

        if ( Result.first != std::end( PlainText ) && Result.second != std::end( rgbPlaintext ) ) {
            throw Exception( _D( "Expected decrypted text comparison failed.\n" ) );
        }

        wprintf(L"Success!\n");

        getch();
        return 0;
    }
    catch ( Exception const & E ) {
        wprintf( E.Message.c_str() );
    }
}

