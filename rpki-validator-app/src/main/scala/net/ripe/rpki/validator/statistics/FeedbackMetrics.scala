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

import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.StringEntity
import org.apache.http.client.HttpClient
import scala.concurrent.stm._
import net.liftweb.json._
import grizzled.slf4j.Logging
import org.apache.http.util.EntityUtils
import org.apache.http.HttpResponse

// See also ba-feedback-server for data and json format that it expects.
case class Metric(name: String, value: String, measuredAt: Long)
object Metric {
  def validatorMetrics(now: Long, startedAt: Long) = {
    Vector(Metric("validator.started.at", startedAt.toString, now))
  }
  def baseMetrics(now: Long): Seq[Metric] = {
    val systemMetrics = {
      val systemProperties = Vector("java.vm.version", "java.vm.vendor", "java.vm.name", "java.version", "java.vendor", "os.name", "os.arch", "os.version")
      systemProperties.map {
        p => Metric(p, System.getProperty(p, ""), now)
      }
    }
    val runtimeMetrics = {
      val runTime = Runtime.getRuntime
      Vector(
        Metric("runtime.processors.available", runTime.availableProcessors.toString, now),
        Metric("runtime.memory.total", runTime.totalMemory.toString, now),
        Metric("runtime.memory.free", runTime.freeMemory.toString, now),
        Metric("runtime.memory.max", runTime.maxMemory.toString, now))
    }

    systemMetrics ++ runtimeMetrics
  }
}

class FeedbackMetrics(httpClient: HttpClient, feedbackUri: String) extends Logging {
  private implicit val formats: Formats = DefaultFormats

  type Metrics = Seq[Metric]

  private val enabledRef = Ref(initialValue = false)
  private[statistics] val queuedMetrics: Ref[Seq[Metrics]] = Ref(Vector.empty)

  def enabled(implicit mt: MaybeTxn) = enabledRef.single.get
  def enabled_=(value: Boolean)(implicit mt: MaybeTxn) = atomic { implicit transaction =>
    enabledRef.set(value)
    if (!value) {
      queuedMetrics.set(Vector.empty)
    }
  }

  def store(metrics: Metrics)(implicit mt: MaybeTxn): Unit = atomic { implicit transaction =>
    if (enabledRef.get) {
      debug("storing %s metrics" format metrics.size)
      queuedMetrics.transform { queued => queued :+ metrics takeRight 100 }
    } else {
      debug("NOT storing %s metrics, did you enable feedback?" format metrics.size)
    }
  }

  def sendMetrics(): Unit = {
    require(Txn.findCurrent.isEmpty, "STM transaction not supported")

    val metrics = queuedMetrics.single.swap(Vector.empty)
    if (metrics.nonEmpty) {
      try {
        val response = postMetrics(metrics)

        response.getStatusLine.getStatusCode match {
          case code if code >= 200 && code < 300 =>
            logger.info("sent " + metrics.size + " telemetry metrics to " + feedbackUri)
          case _ =>
            logger.debug("failed to submit usage metrics to %s: %s".format(feedbackUri, response.getStatusLine))
            queuedMetrics.single.transform { queued => metrics ++ queued }
        }
      } catch {
        case e: Exception =>
          logger.debug("failed to submit usage metrics to %s: %s".format(feedbackUri, e), e)
          queuedMetrics.single.transform { queued => metrics ++ queued }
      }
    }
  }

  private def postMetrics(metrics: Seq[Metrics]): HttpResponse = {
    val metricsJsonList = Extraction.decompose(metrics.flatten)
    val body = JObject(List(JField("metrics", metricsJsonList)))
    val content = new StringEntity(compact(render(body)))

    val post = new HttpPost(feedbackUri)
    post.addHeader("content-type", "application/json")
    post.setEntity(content)

    val response = httpClient.execute(post)
    EntityUtils.consume(response.getEntity)

    response
  }
}
