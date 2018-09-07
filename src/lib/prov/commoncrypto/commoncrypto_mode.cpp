/*
* Cipher Modes via CommonCrypto
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cipher_mode.h>
#include <botan/internal/rounding.h>
#include <botan/internal/commoncrypto.h>

#include <limits.h>
#include <CommonCrypto/CommonCrypto.h>

namespace Botan {

namespace {

class CommonCrypto_Cipher_Mode final : public Cipher_Mode
   {
   public:
      CommonCrypto_Cipher_Mode(const std::string& name,
            CCAlgorithm algo, uint32_t block_size,
            Key_Length_Specification spec, Cipher_Dir direction);
      ~CommonCrypto_Cipher_Mode();

      std::string provider() const override { return "commoncrypto"; }
      std::string name() const override { return m_mode_name; }

      void start_msg(const uint8_t nonce[], size_t nonce_len) override;
      size_t process(uint8_t msg[], size_t msg_len) override;
      void finish(secure_vector<uint8_t>& final_block, size_t offset0) override;
      size_t output_length(size_t input_length) const override;
      size_t update_granularity() const override;
      size_t minimum_final_size() const override;
      size_t default_nonce_length() const override;
      bool valid_nonce_length(size_t nonce_len) const override;
      void clear() override;
      void reset() override;
      Key_Length_Specification key_spec() const override;

   private:
      void key_schedule(const uint8_t key[], size_t length) override;

      const std::string m_mode_name;
      CCAlgorithm m_algo;
      const Cipher_Dir m_direction;
      size_t m_block_size;
      Key_Length_Specification m_cipher_key_spec;
      CCCryptorRef m_cipher = nullptr;
      bool m_key_set;
      bool m_nonce_set;
   };

CommonCrypto_Cipher_Mode::CommonCrypto_Cipher_Mode(const std::string& name,
            CCAlgorithm algo, uint32_t block_size,
            Key_Length_Specification spec, Cipher_Dir direction) :
   m_mode_name(name),
   m_algo(algo),
   m_block_size(block_size),
   m_cipher_key_spec(spec),
   m_direction(direction),
   m_key_set(false),
   m_nonce_set(false)
   {
   }

CommonCrypto_Cipher_Mode::~CommonCrypto_Cipher_Mode()
   {
    if (m_cipher) {
      CCCryptorRelease(m_cipher);
    }
   }

void CommonCrypto_Cipher_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   verify_key_set(m_key_set);

   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);
   if(nonce_len)
      {
        CCCryptorStatus status = CCCryptorReset(m_cipher, nonce);
        if (status != kCCSuccess) {
          throw CommonCrypto_Error("CCCryptorReset", status);
        }
      }
   m_nonce_set = true;
   }

size_t CommonCrypto_Cipher_Mode::process(uint8_t msg[], size_t msg_len)
   {
   verify_key_set(m_key_set);
   BOTAN_STATE_CHECK(m_nonce_set);

   if(msg_len == 0)
      return 0;
   if(msg_len > INT_MAX)
      throw Internal_Error("msg_len overflow");
   size_t outl = msg_len;
   secure_vector<uint8_t> out(outl);

    CCCryptorStatus status = CCCryptorUpdate(m_cipher, msg, msg_len,
      out.data(), msg_len, &outl);
    if (status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorUpdate", status);
    }
    memcpy(msg, out.data(), outl);

   return outl;
   }

void CommonCrypto_Cipher_Mode::finish(secure_vector<uint8_t>& buffer,
                                 size_t offset)
   {
   verify_key_set(m_key_set);

   BOTAN_ASSERT(buffer.size() >= offset, "Offset ok");
   uint8_t* buf = buffer.data() + offset;
   const size_t buf_size = buffer.size() - offset;

   size_t written = process(buf, buf_size);
   size_t outl = buf_size - written;
   secure_vector<uint8_t> out(outl);

    CCCryptorStatus status = CCCryptorFinal(
      m_cipher, out.data(), out.size(), &outl);
    if (status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorUpdate", status);
    }

   memcpy(buf + written, out.data(), outl);
   written += outl;
   buffer.resize(offset + written);
   }

size_t CommonCrypto_Cipher_Mode::update_granularity() const
   {
   return m_block_size * BOTAN_BLOCK_CIPHER_PAR_MULT;
   }

size_t CommonCrypto_Cipher_Mode::minimum_final_size() const
   {
   return 0; // no padding
   }

size_t CommonCrypto_Cipher_Mode::default_nonce_length() const
   {
   return m_block_size;
   }

bool CommonCrypto_Cipher_Mode::valid_nonce_length(size_t nonce_len) const
   {
   return (nonce_len == 0 || nonce_len == m_block_size);
   }

size_t CommonCrypto_Cipher_Mode::output_length(size_t input_length) const
   {
   if(input_length == 0)
      return m_block_size;
   else
      return round_up(input_length, m_block_size);
   }

void CommonCrypto_Cipher_Mode::clear()
   {
    m_key_set = false;

     if (m_cipher == nullptr) {
       return;
     }

    if (m_cipher) {
      CCCryptorRelease(m_cipher);
      m_cipher = nullptr;
    }
   }

void CommonCrypto_Cipher_Mode::reset()
   {
     if (m_cipher == nullptr) {
       return;
     }
    CCCryptorStatus status = CCCryptorReset(m_cipher, nullptr);
    if (status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorReset", status);
    }
   }

Key_Length_Specification CommonCrypto_Cipher_Mode::key_spec() const
   {
   return m_cipher_key_spec;
   }

void CommonCrypto_Cipher_Mode::key_schedule(const uint8_t key[], size_t length)
   {
    CCCryptorStatus status;
    CCOperation op = m_direction == ENCRYPTION ? kCCEncrypt : kCCDecrypt;
    status = CCCryptorCreate(op, m_algo, 0, key, length, nullptr, &m_cipher);
    if (status != kCCSuccess) {
      throw CommonCrypto_Error("CCCryptorCreate", status);
    }

    m_key_set = true;
   }
}

Cipher_Mode*
make_commoncrypto_cipher_mode(const std::string& name, Cipher_Dir direction)
   {
#define MAKE_COMMONCRYPTO_MODE(algo, block_size, kl_fixed) \
   new CommonCrypto_Cipher_Mode(name, algo, block_size, \
    Key_Length_Specification(kl_fixed), direction)

#if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_MODE_CBC)
   if(name == "AES-128/CBC/NoPadding")
      return MAKE_COMMONCRYPTO_MODE(kCCAlgorithmAES, kCCBlockSizeAES128, kCCKeySizeAES128);
   if(name == "AES-192/CBC/NoPadding")
      return MAKE_COMMONCRYPTO_MODE(kCCAlgorithmAES, kCCBlockSizeAES128, kCCKeySizeAES192);
   if(name == "AES-256/CBC/NoPadding")
      return MAKE_COMMONCRYPTO_MODE(kCCAlgorithmAES, kCCBlockSizeAES128, kCCKeySizeAES256);
#endif

#if defined(BOTAN_HAS_DES) && defined(BOTAN_HAS_MODE_CBC)
   if(name == "DES/CBC/NoPadding")
      return MAKE_COMMONCRYPTO_MODE(kCCAlgorithmDES, kCCBlockSizeDES, kCCKeySizeDES);
#endif

#undef MAKE_COMMONCRYPTO_MODE
   return nullptr;
   }

}
