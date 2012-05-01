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
package statistics

import java.util.Date
import org.joda.time.DateTimeUtils
import org.apache.http.impl.client.DefaultHttpClient
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.StringEntity
import org.apache.http.client.HttpClient
import scala.concurrent.stm._
import net.liftweb.json._
import grizzled.slf4j.Logging

// See also ba-feedback-server for data and json format that it expects.
case class Metric(name: String, value: String, measuredAt: Long)

class FeedbackMetrics(val httpClient: HttpClient) extends Logging {
  private implicit val formats: Formats = DefaultFormats

  val serverUri = "https://ba-feedback-server.ripe.net/metrics/rpki-validator"

  type Metrics = Seq[Metric]

  private[statistics] val queuedMetrics: Ref[Seq[Metrics]] = Ref(Vector.empty)

  def store(metrics: Metrics): Unit = {
    queuedMetrics.single.transform { queued => queued :+ metrics takeRight 100 }
  }

  def sendMetrics(): Unit = {
    val post = new HttpPost(serverUri)

    val metrics = queuedMetrics.single.swap(Vector.empty)
    try {
      if (metrics.nonEmpty) {
        val metricsJsonList = Extraction.decompose(metrics.flatten)
        val body = JObject(List(JField("metrics", metricsJsonList)))
        val content = new StringEntity(compact(render(body)))

        post.setEntity(content)

        val response = httpClient.execute(post)

        response.getStatusLine.getStatusCode match {
          case code if code >= 200 && code < 300 => // all is well
          case _ =>
            queuedMetrics.single.transform { queued => metrics ++ queued }
            warn("failed to submit usage metrics to %s: %s".format(serverUri, response.getStatusLine))
        }
      }
    } catch {
      case e: Exception =>
        queuedMetrics.single.transform { queued => metrics ++ queued }
        warn("failed to submit usage metrics to %s: %s".format(serverUri, e), e)
    }

  }

  def getJvmStats = {

    val now = DateTimeUtils.currentTimeMillis

    val systemProperties = List("java.vm.version", "java.vm.vendor", "java.vm.name", "java.version", "java.vendor", "os.name", "os.arch", "os.version")
    val runTime = Runtime.getRuntime

    systemProperties.map {
      p => Metric(p, System.getProperty(p, ""), now)
    } ++ List(
      Metric("runtime.processors.available", runTime.availableProcessors.toString, now),
      Metric("runtime.memory.total", runTime.totalMemory.toString, now),
      Metric("runtime.memory.free", runTime.freeMemory.toString, now),
      Metric("runtime.memory.max", runTime.maxMemory.toString, now))
  }

}

object FeedbackMetrics extends FeedbackMetrics(new DefaultHttpClient())
