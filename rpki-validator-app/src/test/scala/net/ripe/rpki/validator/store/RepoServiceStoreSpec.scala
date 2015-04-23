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
package net.ripe.rpki.validator.store

import java.net.URI

import org.joda.time.Instant
import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.prop.GeneratorDrivenPropertyChecks

class RepoServiceStoreSpec extends PropSpec with GeneratorDrivenPropertyChecks with ShouldMatchers {

  val instantGenerator: Gen[Instant] = for {
    long <- Arbitrary.arbitrary[Long]
  } yield new Instant(long)

  val uriGenerator: Gen[URI] = for {
    scheme <- Gen.oneOf("http", "rsync")
    host <- Gen.alphaStr suchThat (_.length > 0)
    path <- Gen.alphaStr suchThat (_.length > 0)
  } yield new URI(scheme, host, s"/$path", null)

  implicit val arbInstant: Arbitrary[Instant] = Arbitrary(instantGenerator)
  implicit val arbUri: Arbitrary[URI] = Arbitrary(uriGenerator)

  property("getLastFetchTime should return time of updateLastFetchTime") {
    forAll { (i: Instant, u: URI) =>
      RepoServiceStore.updateLastFetchTime(u, "tag", i)
      RepoServiceStore.getLastFetchTime(u, "tag") should be(i);
    }
  }

}
