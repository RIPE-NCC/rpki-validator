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

import java.io.File
import net.ripe.rpki.validator.support.ValidatorTestCase

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class ApplicationOptionsTest extends ValidatorTestCase {
  import scala.concurrent.duration._

  test("Should use 8080 as default http port") {
    ApplicationOptions.httpPort should equal(8080)
  }

  test("Should disable kiosk mode by default") {
    ApplicationOptions.httpKioskEnabled should equal(false)
  }

  test("Should use admin as default kiosk user") {
    ApplicationOptions.httpKioskUser should equal("admin")
  }

  test("Should use admin as default kiosk pass") {
    ApplicationOptions.httpKioskPass should equal("admin")
  }

  test("Should use 8282 as default rtr port") {
    ApplicationOptions.rtrPort should equal(8282)
  }

  test("Should send rtr notify by default") {
    ApplicationOptions.rtrSendNotify should equal(true)
  }

  test("Should close rtr on error by default") {
    ApplicationOptions.rtrCloseOnError should equal(true)
  }

  test("Should use data/data.json as default data file") {
    ApplicationOptions.dataFileLocation should equal(new File("data/data.json"))
  }

  test("Should use conf/tal as default tal dir") {
    ApplicationOptions.talDirLocation should equal(new File("conf/tal"))
  }

  test("Should use conf/ssl as default trusted ssl certificates dir") {
    ApplicationOptions.trustedSslCertsLocation should equal(new File("conf/ssl"))
  }

  test("Should use tmp as default work directory") {
    ApplicationOptions.workDirLocation should equal(new File("tmp"))
  }

  test("Should use log/access.log as default access log") {
    ApplicationOptions.accessLogFileName should equal("log/access.log")
  }

  test("Should use log/validator.log as default location for application log") {
    ApplicationOptions.applicationLogFileName should equal("log/validator.log")
  }

  test("Should use log/rtr.log as default location for application log") {
    ApplicationOptions.rtrLogFileName should equal("log/rtr.log")
  }

  test("Should use 3 hours as the default interval for validation") {
    ApplicationOptions.validationInterval should equal(10.minutes)
  }

  test("Should use data/rsync as the default directory for rsync-based repositories") {
    ApplicationOptions.rsyncDirLocation should equal("data/rsync")
  }
}
