/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PWDHASH_H_
#define BOTAN_PWDHASH_H_

#include <botan/types.h>
#include <string>
#include <memory>
#include <vector>
#include <chrono>

namespace Botan {

/**
* Base class for password based key derivation functions.
*
* Converts a password into a key using a salt and iterated hashing to
* make brute force attacks harder.
*/
class BOTAN_PUBLIC_API(2,8) PasswordHash
   {
   public:
      virtual ~PasswordHash() = default;

      virtual std::string to_string() const = 0;

      /**
      * Derive a key from a password
      *
      * @param out buffer to store the derived key, must be of out_len bytes
      * @param out_len the desired length of the key to produce
      * @param password the password to derive the key from
      * @param password_len the length of password in bytes
      * @param salt a randomly chosen salt
      * @param salt_len length of salt in bytes
      */
      virtual void derive_key(uint8_t out[], size_t out_len,
                              const char* password, const size_t password_len,
                              const uint8_t salt[], size_t salt_len) const = 0;

      // TODO DER_Encode
   };

class BOTAN_PUBLIC_API(2,8) PasswordHashFamily
   {
   public:
      /**
      * Create an instance based on a name
      * If provider is empty then best available is chosen.
      * @param algo_spec algorithm name
      * @param provider provider implementation to choose
      * @return a null pointer if the algo/provider combination cannot be found
      */
      static std::unique_ptr<PasswordHashFamily> create(const std::string& algo_spec,
                                                        const std::string& provider = "");

      /**
      * Create an instance based on a name, or throw if the
      * algo/provider combination cannot be found. If provider is
      * empty then best available is chosen.
      */
      static std::unique_ptr<PasswordHashFamily>
         create_or_throw(const std::string& algo_spec,
                         const std::string& provider = "");

      /**
      * @return list of available providers for this algorithm, empty if not available
      */
      static std::vector<std::string> providers(const std::string& algo_spec);

      virtual ~PasswordHashFamily() = default;

      /**
      * @return name of this PasswordHash
      */
      virtual std::string name() const = 0;

      /**
      * Return a new parameter set tuned for this machine
      * @param output_length how long the output length will be
      * @param msec the desired execution time in milliseconds
      */
      virtual std::unique_ptr<PasswordHash> tune(size_t output_len, std::chrono::milliseconds msec) const = 0;

      /**
      * Return some default parameter set for this PBKDF that should be good
      * enough for most users. The value returned may change over time as
      * processing power and attacks improve.
      */
      virtual std::unique_ptr<PasswordHash> default_params() const = 0;

      // TODO from_configuration(const char* str, size_t i1, size_t i2, size_t i3, size_t i4); ?
   };

}

#endif
