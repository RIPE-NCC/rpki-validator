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

import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import java.io.File

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class OptionsTest extends FunSuite with ShouldMatchers {

  def defaultOptions = Options.defaults
  def overrideOptions(optionName: String, optionValue: String) = Options.parse(Array(optionName, optionValue)).right.get

  test("Should use conf/log4j.xml as default location for log4j config") {
    val subject = defaultOptions
    subject.log4jConfigurationFileLocation should equal(new File("conf/log4j.xml"))
  }

  test("Should use optional/config/path/log4j.xml for log4j config") {
    val subject = overrideOptions("--config-dir", "optional/config/path")
    subject.log4jConfigurationFileLocation should equal(new File("optional/config/path/log4j.xml"))
  }

  test("Should use data/data.json as default data file") {
    val subject = defaultOptions
    subject.dataFileLocation should equal(new File("data/data.json"))
  }

  test("Should allow overriding base dir for data file") {
    val subject = overrideOptions("--data-dir", "optional/data")
    subject.dataFileLocation should equal(new File("optional/data/data.json"))
  }

  test("Should use conf/tal as default tal dir") {
    val subject = defaultOptions
    subject.talDirLocation should equal(new File("conf/tal"))
  }

  test("Should allow overriding tal dir") {
    val subject = overrideOptions("--tal-dir", "/some/location/tal")
    subject.talDirLocation should equal(new File("/some/location/tal"))
  }

  test("Should use tmp as default work directory") {
    val subject = defaultOptions
    subject.workDirLocation should equal(new File("tmp"))
  }

  test("Should allow overriding work directory") {
    val subject = overrideOptions("--work-dir", "/some/other/tmp")
    subject.workDirLocation should equal(new File("/some/other/tmp"))
  }

  test("Should use log/access.log as default access log") {
    val subject = defaultOptions
    subject.accessLogFileName should equal("log/access.log")
  }

  test("Should allow overriding access log location") {
    val subject = overrideOptions("--access-log", "/some/other/access.log")
    subject.accessLogFileName should equal("/some/other/access.log")
  }


}
