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
package net.ripe.rpki.validator.models.validation

import java.io.File
import java.net.URI
import java.util.Collections

import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.validator.config.MemoryImage
import net.ripe.rpki.validator.models._
import net.ripe.rpki.validator.support.ValidatorTestCase
import net.ripe.rpki.validator.util.TrustAnchorLocator
import org.joda.time.{Instant, DateTime}
import org.scalatest.BeforeAndAfter

import scala.concurrent.stm._
import scalaz.Failure

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class TrackValidationProcessTest extends ValidatorTestCase with BeforeAndAfter {

  class MyTrackValidationProcessTrustAnchor(trustAnchors: Seq[TrustAnchor]) extends MyValidationProcess with TrackValidationProcess {
    override val memoryImage = Ref(MemoryImage(Filters(), Whitelist(), new TrustAnchors(trustAnchors), ValidatedObjects(new TrustAnchors(trustAnchors))))
    override def runProcess(forceNewFetch: Boolean) = { super.runProcess(false) }
  }

  val tal = new TrustAnchorLocator(new File(""),
    "caName",
    Collections.singletonList(URI.create("rsync://rpki.ripe.net/root.cer")),
    "publicKeyInfo",
    Collections.emptyList())

  test("should fail with no processable trust anchor") {
    val subject = new MyTrackValidationProcessTrustAnchor(Seq.empty[TrustAnchor])

    val result = subject.runProcess(false)
    result should equal(Failure("Trust anchor not idle or enabled"))
  }

  test("should not process disabled trust anchors") {
    val subject = new MyTrackValidationProcessTrustAnchor(Seq(TrustAnchor(tal, Idle(new DateTime()), false)))

    val result = subject.runProcess(false)
    result should equal(Failure("Trust anchor not idle or enabled"))
  }

  test("should not process already running trust anchors") {
    val subject = new MyTrackValidationProcessTrustAnchor(Seq(TrustAnchor(tal, Running(""), true)))

    val result = subject.runProcess(false)
    result should equal(Failure("Trust anchor not idle or enabled"))
  }
}

class MyValidationProcess extends ValidationProcess {
  val certificateUri = URI.create("rsync://rpki.ripe.net/rootcer")

  override def exceptionHandler = {
    case e: Exception => Failure("")
  }
  override def validateObjects(certificate: CertificateRepositoryObjectValidationContext, forceNewFetch: Boolean, validationStart: Instant) = Seq.empty[ValidatedObject]
  override def finishProcessing() {}

  override val trustAnchorLocator = new TrustAnchorLocator(new File(""),
                                                           "caName",
                                                           Collections.singletonList(certificateUri),
                                                           "publicKeyInfo",
                                                           Collections.emptyList())

  override def extractTrustAnchorLocator(forceNewFetch: Boolean, validationStart: Instant) = {
    throw new RuntimeException("Make validation process fail")
  }
}
