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
class RepoServiceStoreTest extends ValidatorTestCase with BeforeAndAfter {

  test("Should not take slashes into account") {
    val t0 = RepoServiceStore.getLastFetchTime(new URI("rsync://host/a"))
    val t1 = t0.plus(10000L)
    val t2 = t0.plus(50000L)

    RepoServiceStore.updateLastFetchTime(new URI("rsync://host/a/"), t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/b")) should be(t1)

    RepoServiceStore.updateLastFetchTime(new URI("rsync://host/a/b"), t2)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/b")) should be(t2)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a")) should be(t1)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host/a/")) should be(t1)

    val t3 = RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/")).plus(20000L)
    RepoServiceStore.updateLastFetchTime(new URI("rsync://host1/b"), t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x/")) should be(t3)
    RepoServiceStore.getLastFetchTime(new URI("rsync://host1/b/x/y")) should be(t3)
  }


}
