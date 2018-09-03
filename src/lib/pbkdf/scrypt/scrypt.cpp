/**
* (C) 2018 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/scrypt.h>
#include <botan/pbkdf2.h>
#include <botan/salsa20.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/os_utils.h>
#include <sstream>

namespace Botan {

std::string Scrypt_Family::name() const
   {
   return "Scrypt";
   }

std::unique_ptr<PasswordHash> Scrypt_Family::default_params() const
   {
   return std::unique_ptr<PasswordHash>(new Scrypt(32768, 8, 1));
   }

std::unique_ptr<PasswordHash> Scrypt_Family::tune(size_t output_length, std::chrono::milliseconds msec) const
   {
   BOTAN_UNUSED(output_length);
   return std::unique_ptr<PasswordHash>(new Scrypt(msec));
   }

std::unique_ptr<PasswordHash> Scrypt_Family::from_configuration(size_t N, size_t r, size_t p, size_t, const char*) const
   {
   return std::unique_ptr<PasswordHash>(new Scrypt(N, r, p));
   }

namespace {

void scryptBlockMix(size_t r, uint8_t* B, uint8_t* Y)
   {
   uint32_t B32[16];
   secure_vector<uint8_t> X(64);
   copy_mem(X.data(), &B[(2*r-1)*64], 64);

   for(size_t i = 0; i != 2*r; i++)
      {
      xor_buf(X.data(), &B[64*i], 64);
      load_le<uint32_t>(B32, X.data(), 16);
      Salsa20::salsa_core(X.data(), B32, 8);
      copy_mem(&Y[64*i], X.data(), 64);
      }

   for(size_t i = 0; i < r; ++i)
      {
      copy_mem(&B[i*64], &Y[(i * 2) * 64], 64);
      }

   for(size_t i = 0; i < r; ++i)
      {
      copy_mem(&B[(i + r) * 64], &Y[(i * 2 + 1) * 64], 64);
      }
   }

void scryptROMmix(size_t r, size_t N, uint8_t* B, secure_vector<uint8_t>& V)
   {
   const size_t S = 128 * r;

   for(size_t i = 0; i != N; ++i)
      {
      copy_mem(&V[S*i], B, S);
      scryptBlockMix(r, B, &V[N*S]);
      }

   for(size_t i = 0; i != N; ++i)
      {
      // compiler doesn't know here that N is power of 2
      const size_t j = load_le<uint32_t>(&B[(2*r-1)*64], 0) & (N - 1);
      xor_buf(B, &V[j*S], S);
      scryptBlockMix(r, B, &V[N*S]);
      }
   }

}

Scrypt::Scrypt(size_t N, size_t r, size_t p) :
   m_N(N), m_r(r), m_p(p)
   {
   if(!is_power_of_2(N))
      throw Invalid_Argument("Scrypt N parameter must be a power of 2");

   if(p == 0 || p > 128)
      throw Invalid_Argument("Invalid or unsupported scrypt p");
   if(r == 0 || r > 64)
      throw Invalid_Argument("Invalid or unsupported scrypt r");
   if(N < 1 || N > 4194304)
      throw Invalid_Argument("Invalid or unsupported scrypt N");
   }

std::string Scrypt::to_string() const
   {
   std::ostringstream oss;
   oss << "Scrypt(N=" << m_N << ",r=" << m_r << ",p=" << m_p << ")";
   return oss.str();
   }

Scrypt::Scrypt(std::chrono::milliseconds msec)
   {
   /*
   * Some rough relations between scrypt parameters and runtime.
   * Denote here by stime(N,r,p) the msec it takes to run scrypt.
   *
   * Emperically for smaller sizes:
   * stime(N,8*r,p) / stime(N,r,p) is ~ 6-7
   * stime(N,r,8*p) / stime(N,r,8*p) is ~ 7
   * stime(2*N,r,p) / stime(N,r,p) is ~ 2
   *
   * Compute stime(16384,1,1) as baseline.
   * If msec <= that, just return (16384,1,1)
   */

   const size_t trials = 8;

   // Starting parameters
   m_N = 16384;
   m_r = 1;
   m_p = 1;

   const uint64_t scrypt_start = OS::get_system_timestamp_ns();

   uint8_t output[32] = { 0 };
   for(size_t i = 0; i != trials; ++i)
      {
      scrypt(output, sizeof(output), "test", 4, nullptr, 0, m_N, m_r, m_p);
      }

   const uint64_t scrypt_end = OS::get_system_timestamp_ns();

   // nsec for scrypt(16384,1,1)
   const uint64_t measured_time = (scrypt_end - scrypt_start) / trials;

   const double target_nsec = msec.count() * 1000000.0;

   double est_nsec = measured_time;

   while(est_nsec < target_nsec)
      {
      const double range = target_nsec / est_nsec;

      if(range < 2)
         {
         break;
         }

      if(range > 64)
         {
         m_p *= 8;
         est_nsec *= 7;
         }

      if(range > 8)
         {
         m_r *= 8;
         est_nsec *= 6;
         }

      m_N *= 2;
      est_nsec *= 2;
      }
   }

void Scrypt::derive_key(uint8_t output[], size_t output_len,
                        const char* password, size_t password_len,
                        const uint8_t salt[], size_t salt_len) const
   {
   scrypt(output, output_len,
          password, password_len,
          salt, salt_len,
          N(), r(), p());
   }

void scrypt(uint8_t output[], size_t output_len,
            const char* password, size_t password_len,
            const uint8_t salt[], size_t salt_len,
            size_t N, size_t r, size_t p)
   {
   const size_t S = 128 * r;
   secure_vector<uint8_t> B(p * S);
   // temp space
   secure_vector<uint8_t> V((N+1) * S);

   auto hmac_sha256 = MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

   try
      {
      hmac_sha256->set_key(cast_char_ptr_to_uint8(password), password_len);
      }
   catch(Invalid_Key_Length&)
      {
      throw Exception("Scrypt cannot accept passphrases of the provided length");
      }

   pbkdf2(*hmac_sha256.get(),
          B.data(), B.size(),
          salt, salt_len,
          1);

   // these can be parallel
   for(size_t i = 0; i != p; ++i)
      {
      scryptROMmix(r, N, &B[128*r*i], V);
      }

   pbkdf2(*hmac_sha256.get(),
          output, output_len,
          B.data(), B.size(),
          1);
   }

}
