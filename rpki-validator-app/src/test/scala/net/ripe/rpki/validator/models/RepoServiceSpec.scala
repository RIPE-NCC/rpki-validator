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

import net.ripe.rpki.validator.models.validation.RepoFetcher
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.joda.time.{Duration, Instant}
import org.mockito.Mockito
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepoServiceSpec extends ValidatorTestCase with BeforeAndAfter with MockitoSugar  {

  val fetcher1 = mock[RepoFetcher]
  val fetcher2 = mock[RepoFetcher]

  val repoService1 = new RepoService(fetcher1)
  val repoService2 = new RepoService(fetcher2)

  test("should fetch if URI was never visited") {
    val uri = new URI("http://foo.bar/bla")

    repoService1.visitRepo(uri)
    Mockito.verify(fetcher1).fetchRepo(uri)
  }

  test("should NOT fetch if URI was just visited") {
    val uri = new URI("http://foo.bar/bla")

    repoService1.visitRepo(uri)
    repoService1.visitRepo(uri)

    Mockito.verify(fetcher1).fetchRepo(uri)
    Mockito.verifyNoMoreInteractions(fetcher1)
  }

  test("should fetch object if URI was never visited") {
    val uri = new URI("http://foo.bar/bla.cer")

    repoService1.visitObject(uri)

    Mockito.verify(fetcher1).fetchObject(uri)
  }

  test("should not fetch object if URI was already visited") {
    val uri: URI = new URI("http://foo.bar/bla.cer")

    repoService1.visitObject(uri)
    repoService1.visitObject(uri)

    Mockito.verify(fetcher1, Mockito.times(1)).fetchObject(uri)
  }

  test("fetch time should be recent") {
    val minuteAgo: Instant = Instant.now().minus(Duration.standardMinutes(1))
    val twoMinutes: Duration = Duration.standardMinutes(2)
    repoService1.timeIsRecent(minuteAgo, twoMinutes) should be(true)
  }

  test("fetch time should NOT be recent") {
    val twoMinutesAgo: Instant = Instant.now().minus(Duration.standardMinutes(2))
    val minute: Duration = Duration.standardMinutes(1)
    repoService1.timeIsRecent(twoMinutesAgo, minute) should be(false)
  }
}
