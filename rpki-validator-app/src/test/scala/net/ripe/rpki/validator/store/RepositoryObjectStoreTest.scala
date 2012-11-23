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
package net.ripe.rpki.validator
package store

import models._
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import java.net.URI
import org.scalatest.BeforeAndAfter
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest
import org.apache.commons.codec.binary.Base64
import org.joda.time.DateTimeUtils
import org.joda.time.DateTime

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepositoryObjectStoreTest extends FunSuite with BeforeAndAfter with ShouldMatchers {

  val EXAMPLE_MANIFEST = ManifestCmsTest.getRootManifestCms
  val EXAMPLE_MANIFEST_URI = URI.create("rsync://some.host/example.mft")
  val EXAMPLE_MANIFEST_OBJECT = StoredRepositoryObject(uri = EXAMPLE_MANIFEST_URI, repositoryObject = EXAMPLE_MANIFEST)

  val store = new RepositoryObjectStore(DataSources.InMemoryDataSource)

  before {
    store.clear
  }

  after {
    DateTimeUtils.setCurrentMillisSystem // Don't forget to restore normality
  }

  test("Storing same object multiple times should not fail") {
    store.put(EXAMPLE_MANIFEST_OBJECT)
    store.put(EXAMPLE_MANIFEST_OBJECT)
  }

  test("Should retrieve *latest* Repository Object by url") {
    val mft_uri = URI.create("rsync://some.host/foo/bar/mft.mft")
    val now = new DateTime

    DateTimeUtils.setCurrentMillisFixed(now.getMillis)
    val mft_now = ManifestCmsTest.getRootManifestCms
    val manifest_now_stored = StoredRepositoryObject(uri = mft_uri, repositoryObject = mft_now)
    store.put(manifest_now_stored)

    DateTimeUtils.setCurrentMillisFixed(now.plusDays(1).getMillis)
    val mft_tomorrow = ManifestCmsTest.getRootManifestCms
    val mft_tomorrow_stored = StoredRepositoryObject(uri = mft_uri, repositoryObject = mft_tomorrow)
    store.put(mft_tomorrow_stored)

    store.getLatestByUrl(mft_uri) should equal(Some(mft_tomorrow_stored))
  }

  test("Should retrieve Repository Object by hash") {
    store.put(EXAMPLE_MANIFEST_OBJECT)
    store.getByHash(EXAMPLE_MANIFEST_OBJECT.hash.toArray) should equal(Some(EXAMPLE_MANIFEST_OBJECT))
  }

  test("Should store multiple objects including already existing") {
    val ROA_OBJECT = RoaCmsTest.getRoaCms
    val ROA_RETRIEVED_OBJECT = StoredRepositoryObject(uri = URI.create("rsync://some.host/example.roa"), repositoryObject = ROA_OBJECT)

    store.put(EXAMPLE_MANIFEST_OBJECT)
    store.put(Seq(EXAMPLE_MANIFEST_OBJECT, ROA_RETRIEVED_OBJECT))

    store.getByHash(ROA_RETRIEVED_OBJECT.hash.toArray) should equal(Some(ROA_RETRIEVED_OBJECT))
  }

}