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

import java.util.concurrent.Executors

import net.ripe.rpki.validator.support.ValidatorTestCase
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpGet
import org.apache.http.impl.client.HttpClientBuilder
import org.junit.Ignore
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

import scala.concurrent.duration.Duration
import scala.concurrent.{Await, ExecutionContext, Future}


@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
@Ignore
class ValidationLoadTest extends ValidatorTestCase with BeforeAndAfter with MockitoSugar {

  private val httpRequestConfig = RequestConfig.custom()
    .setConnectTimeout(11 * 1000)
    .setSocketTimeout(29 * 1000)
    .build()

  private val httpClient = HttpClientBuilder.create()
    .useSystemProperties()
    .setDefaultRequestConfig(httpRequestConfig)
    .build()


  test("Should issue a lot of queries") {
    implicit val ec = new ExecutionContext {
      val threadPool = Executors.newFixedThreadPool(1000)

      def execute(runnable: Runnable) {
        threadPool.submit(runnable)
      }
      def reportFailure(t: Throwable) {}
    }

    val f = (1 to 100000).map { i =>
      Future {
        println(s"i = $i")
        val n3 = i % 255
        val asn = i % 1000
        // construct new urls every time to avoid caching
        val url = s"http://127.0.0.1:8080/api/v1/validity/AS$asn/$n3/24"
        val response = httpClient.execute(new HttpGet(url))
        scala.io.Source.fromInputStream(response.getEntity.getContent).getLines().mkString("\n")
      }
    }
    f.foreach(Await.result(_, Duration.Inf))
  }

}
