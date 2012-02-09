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

import grizzled.slf4j.Logging

import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import java.net.URI
import java.io.InputStream

import org.joda.time.DateTime
import org.joda.time.DateTimeUtils

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class SoftwareUpdateCheckerTest extends FunSuite with ShouldMatchers {

  // Note: this should reflect whatever we have in the latest-version.properties file in src/test/resources
  val currentVersion = "2.0.2"
  val expectedNewVersion = "2.0.10"
  val expectedUrl = URI.create("http://www.ripe.net/lir-services/resource-management/certification/tools-and-resources")

  test("should NOT read properties when no choice was made") {
    
    
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = null
      override def getSoftwareUpdateOptions = None
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
  }

  test("should NOT read properties when disabled") {
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = null
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = false))
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
  }

  test("should cache new version details") {
    val countingFetcher = new MockNewVersionDetailFetcher(None)
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = countingFetcher
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    countingFetcher.counter should equal(0)
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
    countingFetcher.counter should equal(1)

    val newVersionDetails2 = checker.getNewVersionDetails
    newVersionDetails2 should equal(newVersionDetails)
    countingFetcher.counter should equal(1)
  }

  test("should read again after 24 hours") {
    val now = new DateTime()
    DateTimeUtils.setCurrentMillisFixed(now.getMillis())

    val countingFetcher = new MockNewVersionDetailFetcher(None)
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = countingFetcher
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    countingFetcher.counter should equal(0)
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
    countingFetcher.counter should equal(1)

    val newVersionDetails2 = checker.getNewVersionDetails
    newVersionDetails2 should equal(newVersionDetails)
    countingFetcher.counter should equal(1)

    DateTimeUtils.setCurrentMillisFixed(now.plusDays(1).plusMillis(1).getMillis())

    val newVersionDetails3 = checker.getNewVersionDetails
    newVersionDetails3 should equal(None)
    countingFetcher.counter should equal(2)

    DateTimeUtils.setCurrentMillisSystem()
  }

  test("should read new version details when upgrade available") {
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = getTestNewVersionDetailFetcher("version.latest=" + expectedNewVersion + "\n" + "version.url=" + expectedUrl)
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(Some(NewVersionDetails(version = expectedNewVersion, url = expectedUrl)))
  }

  test("should return none if we're up to date") {
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = getTestNewVersionDetailFetcher("version.latest=" + currentVersion + "\n" + "version.url=" + expectedUrl)
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)

  }

  test("should return none if version properties can't be read") {
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = getTestNewVersionDetailFetcher("this makes no sense")
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
  }

  test("should return none if fetching string throws exception") {
    val checker = new SoftwareUpdateChecker {
      override def getNewVersionDetailFetcher = new OnlineNewVersionDetailFetcher(currentVersion, () => { throw new RuntimeException() })
      override def getSoftwareUpdateOptions = Some(SoftwareUpdateOptions(enableChoice = true))
      override def getCurrentVersion = currentVersion
    }
    val newVersionDetails = checker.getNewVersionDetails
    newVersionDetails should equal(None)
  }

  // Don't depend on network... but this is how we read the remote file:
  //  test("should read file") {
  //     val url = new java.net.URL("https://certification.ripe.net/content/static/validator/latest-version.properties")
  //     val content = scala.io.Source.fromURL(url, "UTF-8").mkString
  //  }

  private def getTestNewVersionDetailFetcher(propertiesString: String) = {
    new OnlineNewVersionDetailFetcher(currentVersion, () => propertiesString)
  }

}

class MockNewVersionDetailFetcher(details: Option[NewVersionDetails]) extends NewVersionDetailFetcher {

  var counter = 0

  override def readNewVersionDetails: Option[NewVersionDetails] = {
    counter = counter + 1
    details
  }

}

