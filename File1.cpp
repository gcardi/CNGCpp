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

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#pragma comment( lib, "bcrypt" )

std::vector<BYTE> const rgbPlaintext {
//TBytes rgbPlaintext {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 1
};

std::vector<BYTE> const rgbIV {
//TBytes rgbIV {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

std::vector<BYTE> const rgbAES256Key {
//TBytes rgbAES256Key {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

void Check( NTSTATUS ntStatus )
{
    if ( !NT_SUCCESS( ntStatus ) ) {
        throw Exception(
            _D( "CNGCrypt Error 0x%08x" ),
            ARRAYOFCONST( ( ntStatus ) )
        );
    }
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
                const_cast<typename std::iterator_traits<PTI>::value_type*>( &*PlainTextBegin ),
                std::distance( PlainTextBegin, PlainTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( &*InitVectBegin ),
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
        DWORD cbCipherText {};
        Check(
            ::BCryptDecrypt(
                Key.GetHndlr(),
                const_cast<typename std::iterator_traits<CTI>::value_type*>( &*CipherTextBegin ),
                std::distance( CipherTextBegin, CipherTextEnd ),
                nullptr,
                const_cast<typename std::iterator_traits<IVI>::value_type*>( &*InitVectBegin ),
                std::distance( InitVectBegin, InitVectEnd ),
                nullptr,
                {},
                &cbCipherText,
                BCRYPT_BLOCK_PADDING
            )
        );
        return cbCipherText;
    }

    DWORD GetKeyObjectlength() const {
        DWORD Dummy {};
        DWORD KeyObject {};
        Check(
            ::BCryptGetProperty(
                alg_,
                BCRYPT_OBJECT_LENGTH,
                (PBYTE)&KeyObject,
                sizeof(DWORD),
                &Dummy,
                {}
            )
        );
        return KeyObject;
    }

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
        Encrypt(
            Key, PlainTextBegin, PlainTextEnd,
            std::begin( CipherText ), std::end( CipherText ),
            std::begin( IV ), std::end( IV )
        );
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
        Decrypt(
            Key, CipherTextBegin, CipherTextEnd,
            std::begin( PlainText ), std::end( PlainText ),
            std::begin( IV ), std::end( IV )
        );
        return PlainText;
    }

private:
    BCRYPT_ALG_HANDLE alg_ {};

    template<typename IVI>
    void CheckBlockLength( IVI InitVectBegin, IVI InitVectEnd ) const
    {
        // Calculate the block length for the IV.
        auto const IVBlockLength = GetBlockLength();

wprintf( L"Initial Vector Block Length = %d\n", IVBlockLength );

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
                alg_,
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
    void Encrypt( K& Key, PTI PlainTextBegin, PTI PlainTextEnd,
                  CTI CipherTextBegin, CTI CipherTextEnd,
                  IVI InitVectBegin, IVI InitVectEnd )
    {
        CheckBlockLength( InitVectBegin, InitVectEnd );

        DWORD Dummy {};

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
                &Dummy,
                BCRYPT_BLOCK_PADDING
            )
        );
    }

    template<typename K, typename PTI, typename CTI, typename IVI>
    void Decrypt( K& Key, CTI CipherTextBegin, CTI CipherTextEnd,
                  PTI PlainTextBegin, PTI PlainTextEnd,
                  IVI InitVectBegin, IVI InitVectEnd )
    {
        CheckBlockLength( InitVectBegin, InitVectEnd );

        DWORD Dummy {};

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
                &Dummy,
                BCRYPT_BLOCK_PADDING
            )
        );
    }

};
//---------------------------------------------------------------------------

class AESAlgProvSessionMngr : public AlgProvSessionMngr {
public:
    AESAlgProvSessionMngr() : AlgProvSessionMngr{ BCRYPT_AES_ALGORITHM } {}
};
//---------------------------------------------------------------------------

class AESCBCAlgProvSessionMngr : public AESAlgProvSessionMngr {
public:
    AESCBCAlgProvSessionMngr()
    {
        Check(
            ::BCryptSetProperty(
                GetHndlr(),
                BCRYPT_CHAINING_MODE,
                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                sizeof(BCRYPT_CHAIN_MODE_CBC),
                {}
            )
        );
    }
};

//---------------------------------------------------------------------------

class SimmetricKeyMngr {
public:
    template<typename A>
    SimmetricKeyMngr( A& Alg )
      : keyObject_( Alg.GetKeyObjectlength() )
    {
    }

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
                Alg.GetHndlr(),
                &key_,
                keyObject_.data(),
                keyObject_.size(),
                const_cast<typename std::iterator_traits<KI>::value_type*>( &*KeyBegin ),
                std::distance( KeyBegin, KeyEnd ),
                {}
            )
        );
    }

    template<typename A, typename BI>
    void Import( A& Alg, BI BlobBegin, BI BlobEnd )
    {
        Check(
            ::BCryptImportKey(
                Alg.GetHndlr(),
                nullptr,
                BCRYPT_OPAQUE_KEY_BLOB,
                &key_,
                keyObject_.data(),
                keyObject_.size(),
                const_cast<typename std::iterator_traits<BI>::value_type*>( &*BlobBegin ),
                std::distance( BlobBegin, BlobEnd ),
                {}
            )
        );
    }

    std::vector<BYTE> Export() const {
        DWORD cbBlob {};

        Check(
            ::BCryptExportKey(
                key_,
                nullptr,
                BCRYPT_OPAQUE_KEY_BLOB,
                nullptr,
                {},
                &cbBlob,
                {}
            )
        );

        std::vector<BYTE> Ret( cbBlob );

        Check(
            ::BCryptExportKey(
                key_,
                nullptr,
                BCRYPT_OPAQUE_KEY_BLOB,
                Ret.data(),
                Ret.size(),
                &cbBlob,
                {}
            )
        );

        return Ret;
    }


    void ClearKeyObject()
    {
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

int _tmain(int argc, _TCHAR* argv[])
{
    try {
        // Open an algorithm (AES CBC)
        AESCBCAlgProvSessionMngr Alg;

        // Create a simmetric key
        auto Key = std::make_unique<SimmetricKeyMngr>(
            Alg, std::begin( rgbAES256Key ), std::end( rgbAES256Key )
        );

        auto const Blob = Key->Export();

        auto CipherText =
            Alg.Encrypt(
                *Key, std::begin( rgbPlaintext ), std::end( rgbPlaintext ),
                std::begin( rgbIV ), std::end( rgbIV )
            );


        // Destroy the old key and create a new one
        //Key.reset( new SimmetricKeyMngr{ Alg } );
        Key = std::move( std::make_unique<SimmetricKeyMngr>( Alg ) );

        // Import the key from saved blob
        Key->Import( Alg, std::begin( Blob ), std::end( Blob ) );

        // Decrypt ciphered text
        auto PlainText =
            Alg.Decrypt(
                *Key, std::begin( CipherText ), std::end( CipherText ),
                std::begin( rgbIV ), std::end( rgbIV )
            );

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

