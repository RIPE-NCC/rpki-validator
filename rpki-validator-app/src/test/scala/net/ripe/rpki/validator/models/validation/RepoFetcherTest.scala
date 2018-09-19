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

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.fetchers.FetcherConfig
import net.ripe.rpki.validator.store.{CacheStore, DataSources, HttpFetcherStore}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.mock.MockitoSugar

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepoFetcherTest extends ValidatorTestCase with MockitoSugar {

  val storage = new CacheStore(DataSources.InMemoryDataSource)

  val resourceSet1 = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212")
  val resourceSet2 = IpResourceSet.parse("192.169.0.0/16")

  val testCertificate1 = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(resourceSet1)
  val testCertificate2 = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(resourceSet2)

  def inMemoryRepoFetcher(config: FetcherConfig) = {
    val dataSource = DataSources.InMemoryDataSource
    new RepoFetcher(new CacheStore(dataSource), new Fetchers(new HttpFetcherStore(), config))
  }

  test("Should create different directories for different repo URLs") {
    val fetcher = inMemoryRepoFetcher(FetcherConfig(rsyncDir = ApplicationOptions.rsyncDirLocation))

    fetcher.fetchRepo(new URI("rsync://repo1/x/z"))
    fetcher.fetchRepo(new URI("rsync://repo2/y"))

    new File(ApplicationOptions.rsyncDirLocation + "/repo1/x").exists should be(true)
    new File(ApplicationOptions.rsyncDirLocation + "/repo2/y").exists should be(true)
  }
}
