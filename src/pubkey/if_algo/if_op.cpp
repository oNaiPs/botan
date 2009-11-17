/*
* IF (RSA/RW) Operation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/if_op.h>
#include <botan/numthry.h>
#include <future>
#include <thread>

namespace Botan {

/*
* Default_IF_Op Constructor
*/
Default_IF_Op::Default_IF_Op(const BigInt& e, const BigInt& n, const BigInt&,
                             const BigInt& p, const BigInt& q,
                             const BigInt& d1, const BigInt& d2,
                             const BigInt& c)
   {
   powermod_e_n = Fixed_Exponent_Power_Mod(e, n);

   if(d1 != 0 && d2 != 0 && p != 0 && q != 0)
      {
      powermod_d1_p = Fixed_Exponent_Power_Mod(d1, p);
      powermod_d2_q = Fixed_Exponent_Power_Mod(d2, q);
      reducer = Modular_Reducer(p);
      this->c = c;
      this->q = q;
      }
   }

/*
* Default IF Private Operation
*/
BigInt Default_IF_Op::private_op(const BigInt& i) const
   {
   if(q == 0)
      throw Internal_Error("Default_IF_Op::private_op: No private key");

   /*
   * A simple std::bind(powermod_d1_p, i) would work instead of a
   * lambda but GCC 4.5's std::result_of doesn't use decltype and gets
   * confused
   *
   * Todo: use std::async() once it is in GCC
   *    auto future_j1 = std::async(std::bind(powermod_d1_p, i));
   *    BigInt j2 = powermod_d2_q(i);
   *    BigInt j1 = future.get();
   */
   std::packaged_task<BigInt ()> task_j1([&]() { return powermod_d1_p(i); });
   auto future_j1 = task_j1.get_future();

   std::thread thr_j1(std::move(task_j1));

   BigInt j2 = powermod_d2_q(i);

   BigInt j1 = future_j1.get();

   thr_j1.join();

   j1 = reducer.reduce(sub_mul(j1, j2, c));
   return mul_add(j1, q, j2);
   }

}
