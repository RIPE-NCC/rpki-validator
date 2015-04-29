/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.validator.lib

import net.ripe.rpki.validator.support.ValidatorTestCase

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent._
import scala.concurrent.duration._

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class LockerTest extends ValidatorTestCase {

  private def checkLocker(key1: String, key2: String, shouldBlock: Boolean = true) {
    var neverExecutedSimultaneously = true
    val locker = new Locker
    val sleepPeriod = 20
    for (n <- 1 to 100) yield {
      var v1isInProgress = false
      var v2isInProgress = false
      val v1 = future {
        locker.locked(key1) {
          v1isInProgress = true
          Thread.sleep(sleepPeriod)
          val incorrect = if (v2isInProgress) true else false
          v1isInProgress = false
          incorrect
        }
      }

      val v2 = future {
        locker.locked(key2) {
          v2isInProgress = true
          Thread.sleep(sleepPeriod)
          val incorrect = if (v1isInProgress) true else false
          v2isInProgress = false
          incorrect
        }
      }
      val wasIncorrect1: Boolean = Await.result(v1, 500.milliseconds)
      val wasIncorrect2: Boolean = Await.result(v2, 500.milliseconds)
      if (shouldBlock) {
        wasIncorrect1 should be(false)
        wasIncorrect2 should be(false)
      } else {
        if (wasIncorrect1 || wasIncorrect2)
          neverExecutedSimultaneously = false
      }
    }

    if (!shouldBlock) {
      // it would be very surprising if they never messed up
      neverExecutedSimultaneously should be(false)
    }
  }

  test("should lock with the same keys") {
    checkLocker("x", "x")
  }

  test("should not lock with different keys") {
    checkLocker("x", "y", shouldBlock = false)
  }

}
