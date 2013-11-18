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
package config

import net.ripe.ipresource.{IpRange, Asn}
import java.io.File
import org.apache.commons.io.FileUtils
import models._
import lib.UserPreferences
import net.ripe.rpki.validator.support.ValidatorTestCase

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class PersistentDataTest extends ValidatorTestCase {

  val serialiser = new PersistentDataSerialiser

  val data_empty: PersistentData = PersistentData()
  val json_empty: String = """{"schemaVersion":0,"filters":{"entries":[]},"whitelist":{"entries":[]},"userPreferences":{"updateAlertActive":true,"maxStaleDays":0},"trustAnchorData":{}}"""
  val data_some: PersistentData = PersistentData(0,
      Filters(Set(IgnoreFilter(IpRange.parse("192.168.0.0/16")))),
      Whitelist(Set(RtrPrefix(Asn.parse("AS65530"), IpRange.parse("10.0.0.0/8"), None))))
  val json_some: String = """{"schemaVersion":0,"filters":{"entries":[{"prefix":"192.168.0.0/16"}]},"whitelist":{"entries":[{"asn":65530,"prefix":"10.0.0.0/8"}]},"userPreferences":{"updateAlertActive":true,"maxStaleDays":0},"trustAnchorData":{}}"""

  test("serialise empty Whitelist") {
    serialiser.serialise(data_empty) should equal(json_empty)
    serialiser.deserialise(json_empty) should equal(data_empty)
  }

  test("serialise non-empty Whitelist") {
    serialiser.serialise(data_some) should equal(json_some)
    serialiser.deserialise(json_some) should equal(data_some)
  }

  test("serialise Whitelist with maxPrefixLength") {
    val data: PersistentData = PersistentData(0, Filters(), Whitelist(Set(RtrPrefix.validate(Asn.parse("AS65530"),
      IpRange.parse("10.0.0.0/8"), Some(16)).toOption.get)))
    val json: String = """{"schemaVersion":0,"filters":{"entries":[]},"whitelist":{"entries":[{"asn":65530,"prefix":"10.0.0.0/8","maxPrefixLength":16}]},"userPreferences":{"updateAlertActive":true,"maxStaleDays":0},"trustAnchorData":{}}"""
    serialiser.serialise(data) should equal(json)
    serialiser.deserialise(json) should equal(data)
  }

  test("should be backwards compatible with json string without software update preferences or disabled trust anchors list") {
    val json: String = """{"schemaVersion":0}"""
    val data = serialiser.deserialise(json)
    data.userPreferences should equal (UserPreferences())
  }

  test("should be backwards compatible with json string without software maxStaleDays in update preferences") {
    val json: String = """{"schemaVersion":0,"userPreferences":{"updateAlertActive":false}}"""
    val data = serialiser.deserialise(json)
    data.userPreferences should equal (UserPreferences(updateAlertActive = false))
  }

  test("should be backwards compatible with json string with feedback enabled") {
    val json: String = """{"schemaVersion":0,"userPreferences":{"updateAlertActive":false, "enableFeedback":true}}"""
    val data = serialiser.deserialise(json)
    data.userPreferences should equal (UserPreferences(updateAlertActive = false))
  }

  test("serialise Whitelist, maxPrefixLength, preferences and disabled trust anchors list") {
    val data: PersistentData = PersistentData(0, Filters(), Whitelist(Set(RtrPrefix.validate(Asn.parse("AS65530"),
      IpRange.parse("10.0.0.0/8"), Some(16)).toOption.get)), UserPreferences(updateAlertActive = false, maxStaleDays = 5), trustAnchorData = Map("AfriNIC RPKI Root" -> TrustAnchorData(enabled = true)))
    val json: String = """{"schemaVersion":0,"filters":{"entries":[]},"whitelist":{"entries":[{"asn":65530,"prefix":"10.0.0.0/8","maxPrefixLength":16}]},"userPreferences":{"updateAlertActive":false,"maxStaleDays":5},"trustAnchorData":{"AfriNIC RPKI Root":{"enabled":true}}}"""
    serialiser.serialise(data) should equal(json)
    serialiser.deserialise(json) should equal(data)
  }

  test("persist to file") {
    val file = File.createTempFile("test-rpki", ".dat")
    file.deleteOnExit()
    file.delete()

    PersistentDataSerialiser.read(file) should equal(None)

    PersistentDataSerialiser.write(data_empty, file)
    FileUtils.readFileToString(file, "UTF-8") should equal(json_empty)
    PersistentDataSerialiser.read(file) should equal(Some(data_empty))

    PersistentDataSerialiser.write(data_some, file)
    FileUtils.readFileToString(file, "UTF-8") should equal(json_some)
    PersistentDataSerialiser.read(file) should equal(Some(data_some))
  }
}
