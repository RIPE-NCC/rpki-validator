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
package net.ripe.rpki.validator.config

import net.ripe.rpki.validator.config.health.{Code, Health, Status}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.joda.time.DateTime
import org.scalatest.{BeforeAndAfter, BeforeAndAfterAll}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class HealthTest extends ValidatorTestCase with BeforeAndAfterAll with BeforeAndAfter {

  test("Should return OK for empty status list") {
    Health.getValidationTimeStatus(Seq()) should equal(Status.ok)
  }

  test("Should return WARNING for status list with one empty time") {
    Health.getValidationTimeStatus(Seq(None)) should equal(Status.warning("Not all TA's are validated."))
  }

  test("Should return OK for status list with one existing time") {
    val t = new DateTime()
    Health.getValidationTimeStatus(Seq(Some(t))) should equal(Status.ok)
  }

  test("Should return ERROR for status list with one time in the past") {
    val t = new DateTime().minus(ApplicationOptions.validationInterval.length * 5)
    val status = Health.getValidationTimeStatus(Seq(Some(t)))
    status.code should equal(Code.ERROR)
    status.message.getOrElse("").contains("No trust anchors have been validated since") should be(true)
    println(status)
  }

  test("Should return OK for status list with at least one good timestamp") {
    Health.getValidationTimeStatus(Seq(
      None,
      Some(new DateTime().minus(ApplicationOptions.validationInterval.length * 5)),
      Some(new DateTime()))
    ) should equal(Status.ok)
  }

}
