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
package net.ripe.rpki.validator.fetchers

import grizzled.slf4j.Logging
import java.net.URI
import net.ripe.certification.validator.fetchers.{ RpkiRepositoryObjectFetcher, RsyncRpkiRepositoryObjectFetcher }
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.commons.util.Specification

class RemoteObjectFetcher(rsyncFetcher: RsyncRpkiRepositoryObjectFetcher, httpFetcherOption: Option[HttpObjectFetcher]) extends RpkiRepositoryObjectFetcher with Logging {

  val uriMap: Map[URI, URI] = Map(
    URI.create("rsync://rpki.ripe.net/") -> URI.create("http://certification.ripe.net/certification/repository/"),
    URI.create("rsync://localhost:10873/online/") -> URI.create("http://localhost:8080/certification/repository/online/"))

  override def prefetch(uri: URI, result: ValidationResult) {
    httpFetcherOption match {
      case Some(httpFetcher) =>
        mapRsynctoHttpUri(uri) match {
          case Some(httpUri) =>
            httpFetcher.prefetch(httpUri, result)
          case None =>
            rsyncFetcher.prefetch(uri, result)
        }
      case None =>
        rsyncFetcher.prefetch(uri, result)
    }
  }

  override def fetch(uri: URI, fileContentSpecification: Specification[Array[Byte]], result: ValidationResult) = {
    httpFetcherOption match {
      case Some(httpFetcher) =>
        mapRsynctoHttpUri(uri) match {
          case Some(httpUri) =>
            httpFetcher.fetch(httpUri, fileContentSpecification, result)
          case None =>
            rsyncFetcher.fetch(uri, fileContentSpecification, result)
        }
      case None =>
        rsyncFetcher.fetch(uri, fileContentSpecification, result)
    }
  }

  def mapRsynctoHttpUri(uri: URI) = {
    uriMap.find(p => uri.toString.startsWith(p._1.toString)) match {
      case Some((rsyncUri, httpUri)) =>
        Some(URI.create(uri.toString.replace(rsyncUri.toString, httpUri.toString)))
      case _ =>
        None
    }
  }
}
