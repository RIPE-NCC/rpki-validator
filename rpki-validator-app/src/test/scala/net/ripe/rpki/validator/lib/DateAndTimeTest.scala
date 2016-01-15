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
package net.ripe.rpki.validator
package lib

import java.util.TimeZone

import org.joda.time.{DateTimeZone, DateTime, Period}

import support.ValidatorTestCase

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class DateAndTimeTest extends ValidatorTestCase {
  import DateAndTime._

  test("keep first significant field") {
    val period = new Period().withWeeks(3).withDays(6)
    keepMostSignificantPeriodFields(period, 1) should equal(new Period().withWeeks(3))
  }

  test("keep three significant fields") {
    val period = new Period().withWeeks(3).withDays(6).withHours(23).withMinutes(40).withMillis(300)
    keepMostSignificantPeriodFields(period, 3) should equal(new Period().withWeeks(3).withDays(6).withHours(23))
  }

  test("stay within field bounds") {
    val period = new Period().withMillis(300)
    keepMostSignificantPeriodFields(period, 3) should equal(new Period().withMillis(300))
  }

  test("should convert date to utc and format it properly") {
    val dt = new DateTime(2016, 1, 15, 14, 6, 0, 0, DateTimeZone.forTimeZone(TimeZone.getTimeZone("CET")))

    val formatted = formatAsRFC2616(dt)

    formatted should be ("Fri, 15 Jan 2016 13:06:00 UTC")
  }
}
