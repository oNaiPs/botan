/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>
#include <botan/internal/ffi_util.h>
#include <botan/version.h>
#include <botan/mem_ops.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <cstdio>
#include <cstdlib>

namespace Botan_FFI {

int ffi_error_exception_thrown(const char* func_name, const char* exn, int rc)
   {
   if(std::getenv("BOTAN_FFI_PRINT_EXCEPTIONS"))
      {
      std::fprintf(stderr, "in %s exception '%s' returning %d\n", func_name, exn, rc);
      }
   return rc;
   }

int ffi_guard_thunk(const char* func_name, std::function<int ()> thunk)
   {
   try
      {
      return thunk();
      }
   catch(std::bad_alloc&)
      {
      return ffi_error_exception_thrown(func_name, "bad_alloc", BOTAN_FFI_ERROR_OUT_OF_MEMORY);
      }
   catch(Botan_FFI::FFI_Error& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), e.error_code());
      }
   catch(Botan::Lookup_Error& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_NOT_IMPLEMENTED);
      }
   catch(Botan::Invalid_Key_Length& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_INVALID_KEY_LENGTH);
      }
   catch(Botan::Key_Not_Set& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_KEY_NOT_SET);
      }
   catch(Botan::Invalid_Argument& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_BAD_PARAMETER);
      }
   catch(Botan::Not_Implemented& e)
      {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_NOT_IMPLEMENTED);
      }
   catch(std::exception& e)
      {
      return ffi_error_exception_thrown(func_name, e.what());
      }
   catch(...)
      {
      return ffi_error_exception_thrown(func_name, "unknown exception");
      }

   return BOTAN_FFI_ERROR_UNKNOWN_ERROR;
   }

}

extern "C" {

using namespace Botan_FFI;

const char* botan_error_description(int err)
   {
   switch(err)
      {
      case BOTAN_FFI_SUCCESS:
         return "OK";

      case BOTAN_FFI_INVALID_VERIFIER:
         return "Invalid verifier";

      case BOTAN_FFI_ERROR_INVALID_INPUT:
         return "Invalid input";

      case BOTAN_FFI_ERROR_BAD_MAC:
         return "Invalid authentication code";

      case BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE:
         return "Insufficient buffer space";

      case BOTAN_FFI_ERROR_EXCEPTION_THROWN:
         return "Exception thrown";

      case BOTAN_FFI_ERROR_OUT_OF_MEMORY:
         return "Out of memory";

      case BOTAN_FFI_ERROR_BAD_FLAG:
         return "Bad flag";

      case BOTAN_FFI_ERROR_NULL_POINTER:
         return "Null pointer argument";

      case BOTAN_FFI_ERROR_BAD_PARAMETER:
         return "Bad parameter";

      case BOTAN_FFI_ERROR_KEY_NOT_SET:
         return "Key not set on object";

      case BOTAN_FFI_ERROR_INVALID_KEY_LENGTH:
         return "Invalid key length";

      case BOTAN_FFI_ERROR_NOT_IMPLEMENTED:
         return "Not implemented";

      case BOTAN_FFI_ERROR_INVALID_OBJECT:
         return "Invalid object handle";

      case BOTAN_FFI_ERROR_UNKNOWN_ERROR:
         return "Unknown error";
      }

   return "Unknown error";
   }

/*
* Versioning
*/
uint32_t botan_ffi_api_version()
   {
   return BOTAN_HAS_FFI;
   }

int botan_ffi_supports_api(uint32_t api_version)
   {
   // This is the API introduced in 2.8
   if(api_version == 20180713)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.3
   if(api_version == 20170815)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.1
   if(api_version == 20170327)
      return BOTAN_FFI_SUCCESS;

   // This is the API introduced in 2.0
   if(api_version == 20150515)
      return BOTAN_FFI_SUCCESS;

   // Something else:
   return -1;
   }

const char* botan_version_string()
   {
   return Botan::version_cstr();
   }

uint32_t botan_version_major() { return Botan::version_major(); }
uint32_t botan_version_minor() { return Botan::version_minor(); }
uint32_t botan_version_patch() { return Botan::version_patch(); }
uint32_t botan_version_datestamp()  { return Botan::version_datestamp(); }

int botan_constant_time_compare(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return Botan::constant_time_compare(x, y, len) ? 0 : -1;
   }

int botan_same_mem(const uint8_t* x, const uint8_t* y, size_t len)
   {
   return botan_constant_time_compare(x, y, len);
   }

int botan_scrub_mem(void* mem, size_t bytes)
   {
   Botan::secure_scrub_memory(mem, bytes);
   return BOTAN_FFI_SUCCESS;
   }

int botan_hex_encode(const uint8_t* in, size_t len, char* out, uint32_t flags)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      const bool uppercase = (flags & BOTAN_FFI_HEX_LOWER_CASE) == 0;
      Botan::hex_encode(out, in, len, uppercase);
      return BOTAN_FFI_SUCCESS;
      });
   }

int botan_hex_decode(const char* hex_str, size_t in_len, uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      const std::vector<uint8_t> bin = Botan::hex_decode(hex_str, in_len);
      return Botan_FFI::write_vec_output(out, out_len, bin);
      });
   }

int botan_base64_encode(const uint8_t* in, size_t len, char* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      const std::string base64 = Botan::base64_encode(in, len);
      return Botan_FFI::write_str_output(out, out_len, base64);
      });
   }

int botan_base64_decode(const char* base64_str, size_t in_len,
                        uint8_t* out, size_t* out_len)
   {
   return ffi_guard_thunk(BOTAN_CURRENT_FUNCTION, [=]() -> int {
      if(*out_len < Botan::base64_decode_max_output(in_len))
         {
         *out_len = Botan::base64_decode_max_output(in_len);
         return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
         }

      *out_len = Botan::base64_decode(out, std::string(base64_str, in_len));
      return BOTAN_FFI_SUCCESS;
      });
   }

}
