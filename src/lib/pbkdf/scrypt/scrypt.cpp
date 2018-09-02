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

Scrypt_Params::Scrypt_Params(size_t N, size_t r, size_t p) :
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

void Scrypt_Params::derive_key(
   uint8_t out[], size_t out_len,
   const char* passphrase, const size_t pass_len,
   const uint8_t salt[], size_t salt_len) const
   {
   scrypt(out, out_len, passphrase, pass_len, salt, salt_len, *this);
   }

std::string Scrypt_Params::to_string() const
   {
   std::ostringstream oss;
   oss << "N=" << m_N << ",r=" << m_r << ",p=" << m_p << "\n";
   return oss.str();
   }

std::string Scrypt::name() const
   {
   return "Scrypt";
   }

std::unique_ptr<PasswordHash::Params> Scrypt::default_params() const
   {
   return std::unique_ptr<PasswordHash::Params>(new Scrypt_Params(32768, 8, 1));
   }

std::unique_ptr<PasswordHash::Params> Scrypt::tune(size_t output_length, uint32_t msec) const
   {
   BOTAN_UNUSED(output_length);
   return std::unique_ptr<PasswordHash::Params>(new Scrypt_Params(msec));
   }

Scrypt_Params::Scrypt_Params(uint32_t msec)
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
   * Compute stime(8192,1,1) as baseline.
   * If msec <= that, just return (8192,1,1)
   */

   // Starting parameters
   m_N = 8192;
   m_r = 1;
   m_p = 1;

   const uint64_t scrypt_start = OS::get_system_timestamp_ns();

   uint8_t output[32] = { 0 };
   scrypt(output, sizeof(output), "", 0, nullptr, 0, *this);
   const uint64_t scrypt_end = OS::get_system_timestamp_ns();

   // nsec for scrypt(8192,1,1)
   const uint64_t measured_time = scrypt_end - scrypt_start;

   const double target_nsec = msec * 1000000.0;

   double est_nsec = measured_time;
   size_t turn = 0;

   while(est_nsec < target_nsec)
      {
      turn = (turn + 1) % 3;

      const double range = target_nsec / est_nsec;

      if(range < 2)
         {
         break;
         }

      if(turn == 0 && range > 2)
         {
         m_N *= 2;
         est_nsec *= 2;
         }
      else if(turn == 1 && range > 4)
         {
         m_r *= 4;
         est_nsec *= 3.5;
         }
      else if(turn == 2 && range > 4)
         {
         m_p *= 4;
         est_nsec *= 3.5;
         }
      }
   }

void scrypt(uint8_t output[], size_t output_len,
            const std::string& password,
            const uint8_t salt[], size_t salt_len,
            size_t N, size_t r, size_t p)
   {
   Scrypt_Params params(N, r, p);

   scrypt(output, output_len,
          password.c_str(), password.size(),
          salt, salt_len,
          params);
   }

void scrypt(uint8_t output[], size_t output_len,
            const char* password, size_t password_len,
            const uint8_t salt[], size_t salt_len,
            const Scrypt_Params& params)
   {
   const size_t N = params.N();
   const size_t r = params.r();
   const size_t p = params.p();

   const size_t S = 128 * r;
   secure_vector<uint8_t> B(p * S);

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

   // temp space
   secure_vector<uint8_t> V((N+1) * S);

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
