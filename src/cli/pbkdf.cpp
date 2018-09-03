/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "cli.h"

#if defined(BOTAN_HAS_PBKDF)
   #include <botan/pwdhash.h>
   #include <botan/internal/os_utils.h>
#endif

namespace Botan_CLI {

#if defined(BOTAN_HAS_PBKDF)

class PBKDF_Tune final : public Command
   {
   public:
      PBKDF_Tune() : Command("pbkdf_tune --algo=Scrypt --output-len=32 --check msec") {}

      std::string group() const override
         {
         return "passhash";
         }

      std::string description() const override
         {
         return "Tune a PBKDF algo";
         }

      void go() override
         {
         const size_t msec = get_arg_sz("msec");
         const size_t output_len = get_arg_sz("output-len");
         const std::string algo = get_arg("algo");
         const bool check_time = flag_set("check");

         std::unique_ptr<Botan::PasswordHashFamily> pwdhash_fam =
            Botan::PasswordHashFamily::create(algo);

         if(!pwdhash_fam)
            throw CLI_Error_Unsupported("Password hashing", algo);

         std::unique_ptr<Botan::PasswordHash> pwhash =
            pwdhash_fam->tune(output_len, std::chrono::milliseconds(msec));

         if(check_time)
            {
            std::vector<uint8_t> outbuf(output_len);
            const uint8_t salt[8] = { 0 };

            const uint64_t start_ns = Botan::OS::get_system_timestamp_ns();
            pwhash->derive_key(outbuf.data(), outbuf.size(),
                               "test", 4, salt, sizeof(salt));
            const uint64_t end_ns = Botan::OS::get_system_timestamp_ns();

            const uint64_t dur_ns = end_ns - start_ns;

            output() << pwhash->to_string() << " took " << (dur_ns / 1000000.0) << " msec to compute\n";
            }
         else
            {
            output() << pwhash->to_string() << "\n";
            }
         }
   };

BOTAN_REGISTER_COMMAND("pbkdf_tune", PBKDF_Tune);

#endif

}
