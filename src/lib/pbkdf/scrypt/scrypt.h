/**
* (C) 2018 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SCRYPT_H_
#define BOTAN_SCRYPT_H_

#include <botan/pwdhash.h>

namespace Botan {

class BOTAN_PUBLIC_API(2,8) Scrypt_Params : public PasswordHash::Params
   {
   public:
      Scrypt_Params(size_t N, size_t r, size_t p);

      explicit Scrypt_Params(uint32_t msec);

      Scrypt_Params(const Scrypt_Params& other) = default;
      Scrypt_Params& operator=(const Scrypt_Params&) = default;

#if !defined(BOTAN_BUILD_COMPILER_IS_MSVC_2013)
      Scrypt_Params(Scrypt_Params&& other) = default;
      Scrypt_Params& operator=(Scrypt_Params&&) = default;
#endif

      /**
      * Derive a new key under the current Scrypt parameter set
      */
      void derive_key(uint8_t out[], size_t out_len,
                      const char* password, const size_t password_len,
                      const uint8_t salt[], size_t salt_len) const override;

      std::string to_string() const override;

      size_t N() const { return m_N; }
      size_t r() const { return m_r; }
      size_t p() const { return m_p; }
   private:
      size_t m_N, m_r, m_p;
   };

class BOTAN_PUBLIC_API(2,8) Scrypt final : public PasswordHash
   {
   public:
      std::string name() const override;

      std::unique_ptr<Params> tune(size_t output_length, uint32_t msec) const override;

      /**
      * Currently returns (32768,8,1)
      */
      std::unique_ptr<Params> default_params() const override;
   };

/**
* Scrypt key derivation function (RFC 7914)
*
* @param output the output will be placed here
* @param output_len length of output
* @param password the user password
* @param salt the salt
* @param salt_len length of salt
* @param N the CPU/Memory cost parameter, must be power of 2
* @param r the block size parameter
* @param p the parallelization parameter
*
* Suitable parameters for most uses would be N = 32768, r = 8, p = 1
*
* Scrypt uses approximately (p + N + 1) * 128 * r bytes of memory
*/
void BOTAN_UNSTABLE_API scrypt(uint8_t output[], size_t output_len,
                               const char* password, size_t password_len,
                               const uint8_t salt[], size_t salt_len,
                               const Scrypt_Params& params);

/**
* Scrypt key derivation function (RFC 7914)
*
* @param output the output will be placed here
* @param output_len length of output
* @param password the user password
* @param salt the salt
* @param salt_len length of salt
* @param N the CPU/Memory cost parameter, must be power of 2
* @param r the block size parameter
* @param p the parallelization parameter
*
* Suitable parameters for most uses would be N = 32768, r = 8, p = 1
*
* Scrypt uses approximately (p + N + 1) * 128 * r bytes of memory
*
* Deprecated:
*/
void BOTAN_UNSTABLE_API scrypt(uint8_t output[], size_t output_len,
                               const std::string& password,
                               const uint8_t salt[], size_t salt_len,
                               size_t N, size_t r, size_t p);

}

#endif
