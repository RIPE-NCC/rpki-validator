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

import java.net.URI

import net.ripe.rpki.validator.fetchers.Fetcher.{ConnectionError, ParseError}
import net.ripe.rpki.validator.models.validation.RepoFetcher
import net.ripe.rpki.validator.store.RepoServiceStore
import net.ripe.rpki.validator.support.{JunitLoggingSetup, ValidatorTestCase}
import org.joda.time.{Duration, Instant}
import org.mockito.Mockito
import org.mockito.internal.verification.VerificationModeFactory
import org.scalatest.{BeforeAndAfter, BeforeAndAfterEach, FunSuite, Matchers}
import org.scalatest.mock.MockitoSugar

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepoServiceSpec extends FunSuite with Matchers with BeforeAndAfterEach with MockitoSugar  {

  val fetcher = mock[RepoFetcher]

  val repoService = new RepoService(fetcher)

  override def beforeEach() {
    Mockito.reset(fetcher)
    RepoServiceStore.reset()
  }

  test("should fetch if URI was never visited") {
    val uri = new URI("http://foo.bar/bla")

    repoService.visitRepo(false, Instant.now())(uri)
    Mockito.verify(fetcher).fetchRepo(uri)
  }

  test("should NOT fetch if URI was just visited") {
    val uri = new URI("http://foo.bar/bla")

    val firstInstant = Instant.now()
    repoService.visitRepo(false, firstInstant)(uri)
    val secondInstant = firstInstant.toDateTime.plusSeconds(1).toInstant
    repoService.visitRepo(false, secondInstant)(uri)

    Mockito.verify(fetcher, VerificationModeFactory.times(1)).fetchRepo(uri)
  }

  test("should fetch if URI was just visited but forceFetch is true") {
    val uri = new URI("http://foo.bar/bla")

    val firstInstant = Instant.now()
    repoService.visitRepo(false, firstInstant)(uri)
    val secondInstant = firstInstant.toDateTime.plusSeconds(1).toInstant
    repoService.visitRepo(true, secondInstant)(uri)

    Mockito.verify(fetcher, VerificationModeFactory.times(2)).fetchRepo(uri)
  }

  test("should fetch object if URI was never visited") {
    val uri = new URI("http://foo.bar/bla.cer")

    repoService.visitTrustAnchorCertificate(uri, false, Instant.now())

    Mockito.verify(fetcher).fetchTrustAnchorCertificate(uri)
  }

  test("should not fetch object if URI was already visited") {
    val uri: URI = new URI("http://foo.bar/bla.cer")

    repoService.visitTrustAnchorCertificate(uri, false, Instant.now())
    repoService.visitTrustAnchorCertificate(uri, false, Instant.now())

    Mockito.verify(fetcher, Mockito.times(1)).fetchTrustAnchorCertificate(uri)
  }

  test("fetch time should be recent") {
    val minuteAgo: Instant = Instant.now().minus(Duration.standardMinutes(1))
    val twoMinutes: Duration = Duration.standardMinutes(2)
    repoService.timeIsRecent(minuteAgo, twoMinutes, Instant.now(), false) should be(true)
  }

  test("fetch time should NOT be recent") {
    val twoMinutesAgo: Instant = Instant.now().minus(Duration.standardMinutes(2))
    val minute: Duration = Duration.standardMinutes(1)
    repoService.timeIsRecent(twoMinutesAgo, minute, Instant.now(), false) should be(false)
  }

  test("should ignore duration when forceFetch is true") {
    val twoMinutesAgo: Instant = Instant.now().minus(Duration.standardMinutes(1))
    val minute: Duration = Duration.standardMinutes(2)
    repoService.timeIsRecent(twoMinutesAgo, minute, Instant.now(), true) should be(false)
  }

  test("should not update last fetch time in case of connection errors") {
    val uri = new URI("http://foo.bar/bla")

    Mockito.when(fetcher.fetchRepo(uri)).thenReturn(Seq(ParseError(uri, "Cannot parse stuff")))

    val firstInstant = Instant.now()
    repoService.visitRepo(false, firstInstant)(uri)
    repoService.lastFetchTime(uri) should be(firstInstant)

    Mockito.when(fetcher.fetchRepo(uri)).thenReturn(Seq(ConnectionError(uri, "Cannot parse stuff")))

    val secondInstant = firstInstant.toDateTime.plusSeconds(1).toInstant
    repoService.visitRepo(true, secondInstant)(uri)
    // the last fetch time should be still the first one
    repoService.lastFetchTime(uri) should be(firstInstant)
  }

}
