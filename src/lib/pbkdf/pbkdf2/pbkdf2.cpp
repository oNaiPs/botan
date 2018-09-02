/*
* PBKDF2
* (C) 1999-2007 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pbkdf2.h>
#include <botan/exceptn.h>
#include <botan/internal/rounding.h>
#include <botan/internal/os_utils.h>

namespace Botan {

size_t
pbkdf2(MessageAuthenticationCode& prf,
       uint8_t out[],
       size_t out_len,
       const std::string& passphrase,
       const uint8_t salt[], size_t salt_len,
       size_t iterations,
       std::chrono::milliseconds msec)
   {
   try
      {
      prf.set_key(cast_char_ptr_to_uint8(passphrase.data()), passphrase.size());
      }
   catch(Invalid_Key_Length&)
      {
      throw Exception("PBKDF2 with " + prf.name() +
                               " cannot accept passphrases of length " +
                               std::to_string(passphrase.size()));
      }

   if(iterations == 0)
      {
      iterations = tune_pbkdf2(prf, out_len, msec.count());
      }

   pbkdf2(prf, out, out_len, salt, salt_len, iterations);

   return iterations;
   }

size_t tune_pbkdf2(MessageAuthenticationCode& prf,
                   size_t output_length,
                   uint32_t msec)
   {
   const size_t prf_sz = prf.output_length();
   BOTAN_ASSERT_NOMSG(prf_sz > 0);
   secure_vector<uint8_t> U(prf_sz);

   const size_t trial_iterations = 10000;

   const size_t start_nsec = OS::get_system_timestamp_ns();

   // Short output ensures we only need a single PBKDF2 block
   uint8_t out[16] = { 0 };
   uint8_t salt[16] = { 0 };
   pbkdf2(prf, out, sizeof(out), salt, sizeof(salt), trial_iterations);

   const uint64_t end_nsec = OS::get_system_timestamp_ns();

   const uint64_t duration_nsec = end_nsec - start_nsec;

   const uint64_t desired_nsec = msec * 1000000;

   if(duration_nsec < desired_nsec)
      return trial_iterations;

   const size_t blocks_needed = (output_length + prf_sz - 1) / prf_sz;

   const size_t multiplier = (desired_nsec / duration_nsec / blocks_needed);

   if(multiplier == 0)
      return trial_iterations;
   else
      return trial_iterations * multiplier;
   }

void pbkdf2(MessageAuthenticationCode& prf,
            uint8_t out[],
            size_t out_len,
            const uint8_t salt[],
            size_t salt_len,
            size_t iterations)
   {
   clear_mem(out, out_len);

   if(out_len == 0)
      return;

   const size_t prf_sz = prf.output_length();
   BOTAN_ASSERT_NOMSG(prf_sz > 0);

   secure_vector<uint8_t> U(prf_sz);

   uint32_t counter = 1;
   while(out_len)
      {
      const size_t prf_output = std::min<size_t>(prf_sz, out_len);

      prf.update(salt, salt_len);
      prf.update_be(counter++);
      prf.final(U.data());

      xor_buf(out, U.data(), prf_output);

      for(size_t i = 1; i != iterations; ++i)
         {
         prf.update(U);
         prf.final(U.data());
         xor_buf(out, U.data(), prf_output);
         }

      out_len -= prf_output;
      out += prf_output;
      }
   }

size_t
PKCS5_PBKDF2::pbkdf(uint8_t key[], size_t key_len,
                    const std::string& passphrase,
                    const uint8_t salt[], size_t salt_len,
                    size_t iterations,
                    std::chrono::milliseconds msec) const
   {
   return pbkdf2(*m_mac.get(), key, key_len, passphrase, salt, salt_len, iterations, msec);
   }


}
