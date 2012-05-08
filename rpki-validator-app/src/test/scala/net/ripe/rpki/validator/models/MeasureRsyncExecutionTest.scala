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
import java.net.URI
import org.mockito.Mockito._
import scalaz.Failure
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.commons.certification.CertificateRepositoryObject
import net.ripe.commons.certification.validation.{ValidationLocation, ValidationResult}
import net.ripe.certification.validator.util.TrustAnchorLocator
import net.ripe.certification.validator.fetchers.RsyncCertificateRepositoryObjectFetcher
import scala.Predef._
import org.joda.time.{DateTimeUtils, DateTime}
import org.scalatest.{BeforeAndAfter, FunSuite}

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class MeasureRsyncExecutionTest extends FunSuite with ShouldMatchers with BeforeAndAfter {

  private class MyMeasureRsyncExecution extends MyValidationProcess with MeasureRsyncExecution {
  }

  val now = new DateTime()

  val certificateUri = URI.create("rsync://rpki.ripe.net/rootcer")
  val repositoryObject = mock(classOf[CertificateRepositoryObject]);

  before {
    DateTimeUtils.setCurrentMillisFixed(now.getMillis())
  }

  after {
    DateTimeUtils.setCurrentMillisSystem()
  }

  test("should add object fetcher listener") {
    val subject = new MyMeasureRsyncExecution

    val listeners = subject.objectFetcherListeners
    listeners should have size(1)
  }

  test("should add metrics on prefetch success") {
    val subject = new MyMeasureRsyncExecution
    val listener = subject.objectFetcherListeners.head

    listener.afterPrefetchSuccess(certificateUri, validationResultWithMetricName(RsyncCertificateRepositoryObjectFetcher.RSYNC_PREFETCH_VALIDATION_METRIC))

    subject.rsyncMetrics.forall(_.name.contains(certificateUri.getHost.toString)) should be(true)
    subject.rsyncMetrics.forall(_.measuredAt == now.getMillis) should be(true)
  }

  test("should add metrics on fetch success") {
    val subject = new MyMeasureRsyncExecution
    val listener = subject.objectFetcherListeners.head

    listener.afterFetchSuccess(certificateUri, repositoryObject, validationResultWithMetricName(RsyncCertificateRepositoryObjectFetcher.RSYNC_FETCH_FILE_VALIDATION_METRIC))

    subject.rsyncMetrics.forall(_.name.contains(certificateUri.getHost.toString)) should be(true)
    subject.rsyncMetrics.forall(_.measuredAt == now.getMillis) should be(true)
  }

  test("should add metrics on prefetch failure") {
    val subject = new MyMeasureRsyncExecution
    val listener = subject.objectFetcherListeners.head

    listener.afterPrefetchFailure(certificateUri, validationResultWithMetricName(RsyncCertificateRepositoryObjectFetcher.RSYNC_PREFETCH_VALIDATION_METRIC))

    subject.rsyncMetrics.forall(_.name.contains(certificateUri.getHost.toString)) should be(true)
    subject.rsyncMetrics.forall(_.measuredAt == now.getMillis) should be(true)
  }

  test("should add metrics on fetch failure") {
    val subject = new MyMeasureRsyncExecution
    val listener = subject.objectFetcherListeners.head

    listener.afterFetchFailure(certificateUri, validationResultWithMetricName(RsyncCertificateRepositoryObjectFetcher.RSYNC_FETCH_FILE_VALIDATION_METRIC))

    subject.rsyncMetrics.forall(_.name.contains(certificateUri.getHost.toString)) should be(true)
    subject.rsyncMetrics.forall(_.measuredAt == now.getMillis) should be(true)
  }

  def validationResultWithMetricName(name: String) = {
    val validationResult = new ValidationResult()
    validationResult.setLocation(new ValidationLocation(certificateUri))
    validationResult.addMetric(name, "123")
    validationResult
  }
}
