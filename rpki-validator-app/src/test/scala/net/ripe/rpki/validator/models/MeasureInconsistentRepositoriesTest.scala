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
package models

import statistics._
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.rpki.validator.statistics.InconsistentRepositoryChecker
import net.ripe.rpki.validator.statistics.InconsistentRepositoryCheckingTest
import java.net.URI

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class MeasureInconsistentRepositoriesTest extends FunSuite with ShouldMatchers {

  val subject = new TestMeasureInconsistentRepositories

  test("should log statistics") {
    subject.extractInconsistencies(InconsistentRepositoryCheckingTest.INCONSISTENT_OBJECT_SET)

    val metrics = subject.inconsistencyMetrics.map(x => (x.name, x.value)).toMap

    metrics should contain("trust.anchor[rsync://host/ta.cer].repositories.total.count" -> "1")
    metrics should contain("trust.anchor[rsync://host/ta.cer].repositories.inconsistent.count" -> "1")
    metrics should contain("trust.anchor[rsync://host/ta.cer].repository.is.inconsistent" -> "rsync://host/ta.mft")

  }

  class TestMeasureInconsistentRepositories extends MyValidationProcess with MeasureInconsistentRepositories {

    import net.ripe.rpki.validator.util.TrustAnchorLocator
    import java.util.ArrayList

    override val trustAnchorLocator = new TrustAnchorLocator(null, "test ca", URI.create("rsync://host/ta.cer"), "hash", new ArrayList[URI]()) //File file, String caName, URI location, String publicKeyInfo, List<URI> prefetchUris

  }

}