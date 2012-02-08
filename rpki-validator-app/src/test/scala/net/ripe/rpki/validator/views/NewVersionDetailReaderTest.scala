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
package net.ripe.rpki.validator.views
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import java.net.URI
import java.io.InputStream

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class NewVersionDetailReaderTest extends FunSuite with ShouldMatchers {

  // Note: this should reflect whatever we have in the latest-version.properties file in src/test/resources
  val currentVersion = "2.0.2"
  val expectedNewVersion = "2.0.10"
  val expectedUrl = URI.create("http://www.ripe.net/lir-services/resource-management/certification/tools-and-resources")

  test("should read new version details when upgrade available") {
    val reader = new TestableNewVersionDetailReader("/latest-version.properties")
    val newVersionDetails = reader.readNewVersionDetails(currentVersion = currentVersion)
    newVersionDetails should equal(Some(NewVersionDetails(version = expectedNewVersion, url = expectedUrl)))
  }
  
  test("should return none when up to date") {
	  val reader = new TestableNewVersionDetailReader("/latest-version.properties")
	  val newVersionDetails = reader.readNewVersionDetails(currentVersion = expectedNewVersion)
	  newVersionDetails should equal(None)
  }

  test("should return none if version properties can't be read") {
    val reader = new TestableNewVersionDetailReader("doesnotexist")
    val newVersionDetails = reader.readNewVersionDetails(currentVersion = currentVersion)
    newVersionDetails should equal(None)
  }

}

class TestableNewVersionDetailReader(fileLocation: String) extends NewVersionDetailReader {

  override def readNewVersionPropertiesFile(): InputStream = {
    getClass().getResourceAsStream(fileLocation);
  }

}

