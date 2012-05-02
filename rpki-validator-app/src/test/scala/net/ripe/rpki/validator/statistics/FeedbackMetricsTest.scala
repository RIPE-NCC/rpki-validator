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
package net.ripe.rpki.validator.statistics

import scala.concurrent.stm.atomic

import org.apache.http.HttpVersion
import org.apache.http.client.HttpClient
import org.apache.http.client.methods.HttpPost
import org.apache.http.message.BasicHttpResponse
import org.apache.http.message.BasicStatusLine
import org.apache.http.util.EntityUtils
import org.joda.time.DateTimeUtils
import org.junit.runner.RunWith
import org.mockito.ArgumentCaptor
import org.mockito.Matchers._
import org.mockito.Mockito._
import org.scalatest.BeforeAndAfter
import org.scalatest.FunSuite
import org.scalatest.junit.JUnitRunner
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.mock.MockitoSugar

import javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR
import javax.servlet.http.HttpServletResponse.SC_OK

@RunWith(classOf[JUnitRunner])
class FeedbackMetricsTest extends FunSuite with ShouldMatchers with BeforeAndAfter with MockitoSugar {

  val now = DateTimeUtils.currentTimeMillis
  val mockHttpClient = mock[HttpClient]
  val subject = new FeedbackMetrics(mockHttpClient, "http://feedback.ripe.net/metrics/rpki-validator")
  val testMetrics = List(Metric("name", "value", now))

  def resetHttpClient() {
    reset(mockHttpClient)

    val statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, SC_OK, "OK")
    val response = new BasicHttpResponse(statusLine)
    when(mockHttpClient.execute(any(classOf[HttpPost]))).thenReturn(response)
  }

  before {
    resetHttpClient()
    subject.enabled = true
  }

  test("should measure validator information") {
    // Not all properties are tested here.
    val startedAt = now - 5000
    val metrics = Metric.validatorMetrics(now, startedAt, "version")
    metrics should contain(Metric("validator.started.at", startedAt.toString, now))
    metrics should contain(Metric("validator.version", "version", now))
  }

  test("should measure JVM information") {
    // Not all properties are tested here.
    val metrics = Metric.baseMetrics(now)
    metrics should contain(Metric("java.vm.version", System.getProperty("java.vm.version"), now))
    metrics should contain(Metric("runtime.processors.available", Runtime.getRuntime.availableProcessors.toString, now))
  }

  test("should post statistics once") {
    subject.store(testMetrics)
    subject.queuedMetrics.single.get should have size (1)

    // should send to server
    subject.sendMetrics()
    verify(mockHttpClient, times(1)).execute(any(classOf[HttpPost]))
    subject.queuedMetrics.single.get should have size (0)

    // should not send anything to server (already sent)
    reset(mockHttpClient)
    subject.sendMetrics()
    verify(mockHttpClient, never()).execute(any(classOf[HttpPost]))
  }

  test("should send metrics as json using POST") {
    subject.store(testMetrics)

    subject.sendMetrics()

    expectPost { post =>
      post.getMethod should be("POST")
      post.getURI.toString should endWith("/metrics/rpki-validator")
      EntityUtils.toString(post.getEntity) should be("""{"metrics":[{"name":"name","value":"value","measuredAt":%d}]}""" format now)
    }
  }

  test("should re-send metrics that failed with exception") {
    subject.store(testMetrics)

    when(mockHttpClient.execute(any(classOf[HttpPost]))).thenThrow(new RuntimeException("mock exception"))
    subject.sendMetrics()
    subject.queuedMetrics.single.get should have size (1)

    resetHttpClient()
    subject.sendMetrics()
    expectPost { post =>
      EntityUtils.toString(post.getEntity) should be("""{"metrics":[{"name":"name","value":"value","measuredAt":%d}]}""" format now)
    }
  }

  test("should re-send metrics that failed with http error response") {

    subject.store(testMetrics)

    val statusLine = new BasicStatusLine(HttpVersion.HTTP_1_1, SC_INTERNAL_SERVER_ERROR, "mock http response")
    val response = new BasicHttpResponse(statusLine)

    when(mockHttpClient.execute(any(classOf[HttpPost]))).thenReturn(response)
    subject.sendMetrics()
    subject.queuedMetrics.single.get should have size (1)

    resetHttpClient()
    subject.sendMetrics()
    expectPost { post =>
      EntityUtils.toString(post.getEntity) should be("""{"metrics":[{"name":"name","value":"value","measuredAt":%d}]}""" format now)
    }
  }

  test("should combine multiple submitted metrics into a single post to the feedback server") {
    subject.store(testMetrics)
    subject.store(testMetrics)

    subject.sendMetrics()

    expectPost { post =>
      EntityUtils.toString(post.getEntity) should be("""{"metrics":[{"name":"name","value":"value","measuredAt":%d},{"name":"name","value":"value","measuredAt":%d}]}""" format (now, now))
    }
  }

  test("should queue up to 100 measurements") {
    0 to 200 foreach { _ => subject.store(testMetrics) }
    subject.queuedMetrics.single.get should have size (100)
  }

  test("sending metrics does not support STM transaction") {
    import scala.concurrent.stm._

    intercept[RuntimeException] {
      atomic { implicit transaction =>
        subject.sendMetrics()
      }
    }
  }

  test("should clear metrics when feedback is disabled") {
    subject.store(testMetrics)

    subject.enabled = false

    subject.queuedMetrics.single.get should have size (0)
  }

  test("should not store metrics when feedback is disabled") {
    subject.enabled = false
    subject.store(testMetrics)
    subject.queuedMetrics.single.get should have size (0)
  }

  def expectPost(callback: HttpPost => Unit) = {
    val capture = ArgumentCaptor.forClass(classOf[HttpPost])
    verify(mockHttpClient, times(1)).execute(capture.capture)
    callback(capture.getValue)
  }

}