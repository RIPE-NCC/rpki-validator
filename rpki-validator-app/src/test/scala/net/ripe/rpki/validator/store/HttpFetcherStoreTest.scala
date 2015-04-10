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

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.scalatest.BeforeAndAfter

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class HttpFetcherStoreTest extends ValidatorTestCase with BeforeAndAfter {

  val store = new HttpFetcherStore(DataSources.InMemoryDataSource)

  before {
    store.clear()
  }

  test("Store a serial and get it back") {
    val url = new URI("http://bla.bla")
    val sessionId = "aec41310-67e1-429b-9d1b-df30961e9932"
    val serial = BigInt(100)
    store.storeSerial(url, sessionId, serial)

    val s = store.getSerial(url, sessionId)
    s should be(Some(serial))
  }

  test("Store a really big serial number and get it back") {
    val url = new URI("http://bla.bla")
    val sessionId = "aec41310-67e1-429b-9d1b-df30961e9932"
    val serial = BigInt(Long.MaxValue) * 10
    store.storeSerial(url, sessionId, serial)

    val s = store.getSerial(url, sessionId)
    s should be(Some(serial))
  }

  test("Store a serial, updates it and get back the latest one") {
    val url = new URI("http://bla.bla")
    val sessionId = "aec41310-67e1-429b-9d1b-df30961e9932"
    val serial1 = BigInt(100)
    val serial2 = BigInt(101)

    store.storeSerial(url, sessionId, serial1)
    store.getSerial(url, sessionId) should be(Some(serial1))

    store.storeSerial(url, sessionId, serial2)
    store.getSerial(url, sessionId) should be(Some(serial2))
  }

}
