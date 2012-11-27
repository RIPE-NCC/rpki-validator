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
package net.ripe.rpki.validator.models

import org.scalatest.matchers.ShouldMatchers
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import scalaz.Failure
import java.net.URI
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.{DateTimeUtils, DateTime}
import org.scalatest.{BeforeAndAfter, FunSuite}
import java.io.File
import java.util.Collections

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class MeasureValidationProcessTest extends FunSuite with ShouldMatchers with BeforeAndAfter {

  private class MyMeasureValidationProcess extends MyValidationProcess with MeasureValidationProcess {
  }

  val now = new DateTime()

  before {
    DateTimeUtils.setCurrentMillisFixed(now.getMillis())
  }

  after {
    DateTimeUtils.setCurrentMillisSystem()
  }

  test("should generate metric when processing is finished") {
    val subject = new MyMeasureValidationProcess

    subject.finishProcessing()

    val metrics = subject.metrics
    metrics should have size(1)
    metrics(0).name should include(subject.certificateUri.toString)
    metrics(0).name should include("validation.elapsed")
    metrics(0).measuredAt should equal(now.getMillis)
  }

  test("should generate metric when validating objects") {
    val subject = new MyMeasureValidationProcess
    subject.validateObjects(null)

    val metrics = subject.metrics
    metrics should have size(2)

    metrics(0).name should include(subject.certificateUri.toString)
    metrics(0).name should include("extracted.elapsed")
    metrics(0).measuredAt should equal(now.getMillis)

    metrics(1).name should include(subject.certificateUri.toString)
    metrics(1).name should include("validation")
    metrics(1).value should be("OK")
    metrics(1).measuredAt should equal(now.getMillis)
  }

  test("should generate metric when exception is thrown during validation") {
    val subject = new MyMeasureValidationProcess

    subject.runProcess()

    val metrics = subject.metrics
    metrics should have size(2)
    metrics(0).name should include(subject.certificateUri.toString)
    metrics(0).value should include("failed")
    metrics(0).measuredAt should equal(now.getMillis)
  }
}

class MyValidationProcess extends ValidationProcess {
  val certificateUri = URI.create("rsync://rpki.ripe.net/rootcer")

  override def exceptionHandler = {
    case e: Exception => Failure("")
  }
  override def validateObjects(certificate: CertificateRepositoryObjectValidationContext) = Map.empty[URI, ValidatedObject]
  override def finishProcessing() {}
  override val trustAnchorLocator = new TrustAnchorLocator(new File(""), "caName", certificateUri, "publicKeyInfo", Collections.emptyList())
  override def extractTrustAnchorLocator() = { throw new RuntimeException("Make validation process fail") }
}
