/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf.h>
#include <botan/exceptn.h>
#include <botan/scan_name.h>

#if defined(BOTAN_HAS_PBKDF2)
   #include <botan/pbkdf2.h>
#endif

#if defined(BOTAN_HAS_PGP_S2K)
   #include <botan/pgp_s2k.h>
#endif

#if defined(BOTAN_HAS_SCRYPT)
   #include <botan/scrypt.h>
#endif

namespace Botan {

std::unique_ptr<PasswordHash> PasswordHash::create(const std::string& algo_spec,
                                     const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_PBKDF2) && 0
   if(req.algo_name() == "PBKDF2")
      {
      // TODO OpenSSL

      if(provider.empty() || provider == "base")
         {
         if(auto mac = MessageAuthenticationCode::create(req.arg(0)))
            return std::unique_ptr<PasswordHash>(new PKCS5_PBKDF2(mac.release()));

         if(auto mac = MessageAuthenticationCode::create("HMAC(" + req.arg(0) + ")"))
            return std::unique_ptr<PasswordHash>(new PKCS5_PBKDF2(mac.release()));
         }

      return nullptr;
      }
#endif

#if defined(BOTAN_HAS_SCRYPT)
   if(req.algo_name() == "Scrypt")
      {
      return std::unique_ptr<PasswordHash>(new Scrypt);
      }
#endif

#if defined(BOTAN_HAS_PGP_S2K) && 0
   if(req.algo_name() == "OpenPGP-S2K" && req.arg_count() == 1)
      {
      if(auto hash = HashFunction::create(req.arg(0)))
         {
         return std::unique_ptr<PasswordHash>(new OpenPGP_S2K_PasswordHash(hash.release()));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<PasswordHash>
PasswordHash::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto pbkdf = PasswordHash::create(algo, provider))
      {
      return pbkdf;
      }
   throw Lookup_Error("PasswordHash", algo, provider);
   }

std::vector<std::string> PasswordHash::providers(const std::string& algo_spec)
   {
   return probe_providers_of<PasswordHash>(algo_spec, { "base", "openssl" });
   }

}
