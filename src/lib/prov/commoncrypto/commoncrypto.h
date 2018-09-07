/*
* Utils for calling CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_INTERNAL_COMMONCRYPTO_H_
#define BOTAN_INTERNAL_COMMONCRYPTO_H_

#include <botan/pk_ops_fwd.h>
#include <botan/secmem.h>
#include <botan/exceptn.h>
#include <memory>
#include <string>

namespace Botan {

class Cipher_Mode;
class HashFunction;
enum Cipher_Dir : int;

class BOTAN_PUBLIC_API(2,0) CommonCrypto_Error final : public Exception
  {
    public:
      CommonCrypto_Error(const std::string& what) :
        Exception(what + " failed.") {}
  };

/* Cipher Modes */

Cipher_Mode*
make_commoncrypto_cipher_mode(const std::string& name, Cipher_Dir direction);

/* Hash */

std::unique_ptr<HashFunction> make_commoncrypto_hash(const std::string& name);

}

#endif
