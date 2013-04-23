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

import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner
import org.scalatest.matchers.ShouldMatchers

import NumberResources.NumberResourceInterval
import NumberResources.NumberResourceIntervalTree
import net.ripe.ipresource.Asn
import net.ripe.ipresource.IpRange
import net.ripe.rpki.validator.models.RtrPrefix

object NumberResourcesTest {
  import scala.language.implicitConversions
  implicit def LongToAsn(asn: Long): Asn = new Asn(asn)
  implicit def StringToPrefix(s: String): IpRange = IpRange.parse(s)
  implicit def IpRangeToInterval(range: IpRange) = NumberResourceInterval(range.getStart(), range.getEnd())
  implicit def StringToInterval(s: String): NumberResourceInterval = IpRangeToInterval(StringToPrefix(s))
}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class NumberResourcesTest extends FunSpec with ShouldMatchers {
  import NumberResourcesTest._

  val Prefix_10_8 = IpRange.parse("10/8")
  val Prefix_10_9 = IpRange.parse("10/9")

  val Range_10_8 = NumberResourceInterval(Prefix_10_8.getStart(), Prefix_10_8.getEnd())
  val Range_10_9 = NumberResourceInterval(Prefix_10_9.getStart(), Prefix_10_9.getEnd())
  val Range_127_8 = NumberResourceInterval(IpRange.parse("127/8").getStart(), IpRange.parse("127/8").getEnd())

  val RtrPrefix_10_8 = RtrPrefix(65535, Prefix_10_8, None)
  val RtrPrefix_10_9 = RtrPrefix(Asn.parse("AS65530"), Prefix_10_9, None)

  describe("NumberResourceInterval 10/8") {
    it("should contain 10/9") {
      Range_10_8.contains(Range_10_9) should be(true)
    }
    it("should not contain 127/8") {
      Range_10_8.contains(Range_127_8) should be(false)
    }
  }

  describe("Empty NumberResourceIntervalTree") {
    val subject = NumberResourceIntervalTree.empty[RtrPrefix]
    it("should be empty") {
      subject should be('empty)
    }
    it("should not find any match") {
      subject.findExactAndAllLessSpecific(Range_10_8) should be('empty)
    }
  }

  describe("Singleton NumberResourceIntervalTree") {
    val subject = NumberResourceIntervalTree(RtrPrefix_10_8)
    it("should not be empty") {
      subject should not be ('empty)
    }

    it("should find exact match") {
      subject.findExactAndAllLessSpecific(Range_10_8) should contain(RtrPrefix_10_8)
    }

    it("should find containing match") {
      subject.findExactAndAllLessSpecific(Range_10_9) should contain(RtrPrefix_10_8)
    }

    it("should not find range outside") {
      subject.findExactAndAllLessSpecific(Range_127_8) should be('empty)
    }
  }

  describe("Multi-entry NumberResourceIntervalTree") {
    val subject = NumberResourceIntervalTree(RtrPrefix_10_8, RtrPrefix_10_9)
    it("should not be empty") {
      subject should not be ('empty)
    }

    it("should find exact match") {
      subject.findExactAndAllLessSpecific(Range_10_8) should contain(RtrPrefix_10_8)
    }

    it("should find containing matches") {
      subject.findExactAndAllLessSpecific(Range_10_9) should (contain(RtrPrefix_10_8) and contain(RtrPrefix_10_9))
    }

    it("should not find range outside") {
      subject.findExactAndAllLessSpecific(Range_127_8) should be('empty)
    }
  }

  describe("Many distinct entry NumberResourceIntervalTree") {
    val prefixes = (1 to 100) map { i =>
      RtrPrefix(i, IpRange.parse(i + "/8"), None)
    }
    val subject = NumberResourceIntervalTree(prefixes: _*)
    it("should find exact matches") {
      for (prefix <- prefixes) {
        subject.findExactAndAllLessSpecific(prefix.prefix) should (have size (1) and contain(prefix))
      }
    }
    it("should find containing match") {
      subject.findExactAndAllLessSpecific("1/9") should (have size (1) and contain(RtrPrefix(1, "1/8", None)))
      subject.findExactAndAllLessSpecific("33/9") should (have size (1) and contain(RtrPrefix(33, "33/8", None)))
      subject.findExactAndAllLessSpecific("99/9") should (have size (1) and contain(RtrPrefix(99, "99/8", None)))
      subject.findExactAndAllLessSpecific("100/9") should (have size (1) and contain(RtrPrefix(100, "100/8", None)))
    }
  }

  describe("Many overlapping entry NumberResourceIntervalTree") {
    val prefixes = (0 to 30) map { i =>
      RtrPrefix(i, "0/" + i, Some(i))
    }
    val subject = NumberResourceIntervalTree(prefixes: _*)
    it("should find exact matches") {
      for (prefix <- prefixes) {
        subject.findExactAndAllLessSpecific(prefix.prefix) should (have size (prefix.maxPrefixLength.get + 1) and contain(prefix))
      }
    }
    it("should find containing match") {
      subject.findExactAndAllLessSpecific("0/31") should equal(prefixes)
    }
  }
}
