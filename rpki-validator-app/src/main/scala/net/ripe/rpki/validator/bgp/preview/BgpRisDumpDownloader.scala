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
package net.ripe.rpki.validator.bgp.preview

import scala.concurrent.stm.Ref
import java.io.InputStream
import java.util.zip.GZIPInputStream
import javax.servlet.http.HttpServletResponse._
import grizzled.slf4j.Logging
import org.joda.time.DateTime
import akka.dispatch.ExecutionContext
import akka.dispatch.Future
import akka.dispatch.Promise
import com.ning.http.client.AsyncHttpClient
import com.ning.http.client.AsyncCompletionHandler
import com.ning.http.client.Response
import com.ning.http.util.DateUtil

object BgpRisDumpDownloader extends Logging {
  val DEFAULT_URLS = Seq(
    "http://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz",
    "http://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz")

  private lazy val http = new AsyncHttpClient()

  /**
   * Refreshes the given BgpRisDump. If the source information was not modified or could not be retrieved the input dump is returned.
   */
  def download(dump: BgpRisDump)(implicit ec: ExecutionContext): Future[BgpRisDump] = {
    val url = dump.url
    info("Retrieving BGP entries from " + url)

    val request = http.prepareGet(url).setFollowRedirects(true)
    dump.lastModified foreach { lastModified =>
      request.setHeader("If-Modified-Since", DateUtil.formatDate(lastModified.toDate()))
    }

    val result = Promise[BgpRisDump]()
    request.execute(new AsyncCompletionHandler[Unit] {
      override def onCompleted(response: Response) = response.getStatusCode() match {
        case SC_OK =>
          BgpRisDump.parse(new GZIPInputStream(response.getResponseBodyAsStream())) match {
            case Left(exception) =>
              error("Error parsing BGP entries from " + url + ". " + exception.toString(), exception)
              result.success(dump)
            case Right(entries) =>
              val modified = lastModified(response)
              info("Retrieved " + entries.size + " entries from " + url + ", last modified at " + modified.getOrElse("unknown"))
              result.success(dump.copy(lastModified = modified, entries = entries))
          }
        case SC_NOT_MODIFIED if dump.lastModified.isDefined =>
          info("BGP entries from " + url + " were not modified since " + dump.lastModified.get)
          result.success(dump)
        case _ =>
          warn("error retrieving BGP entries from " + url + ". Code: " + response.getStatusCode() + " " + response.getStatusText())
          result.success(dump)
      }
      override def onThrowable(t: Throwable) = {
        error("error retrieving BGP entries from " + url, t)
        result.success(dump)
      }
    })

    result
  }

  private def lastModified(response: Response) = Option(response.getHeader("Last-Modified")) flatMap { v =>
    try {
      Some(new DateTime(DateUtil.parseDate(v)))
    } catch {
      case _ => None
    }
  }

}
