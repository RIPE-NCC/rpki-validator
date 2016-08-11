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
package net.ripe.rpki.validator.models

import java.net.URI

import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.fetchers.Fetcher
import net.ripe.rpki.validator.fetchers.Fetcher.{ConnectionError, Error}
import net.ripe.rpki.validator.lib.Locker
import net.ripe.rpki.validator.models.validation.RepoFetcher
import net.ripe.rpki.validator.store.RepoServiceStore
import org.joda.time.{Duration, Instant}

import scala.Seq
import scala.collection._

object RepoServiceErrors {
  val lastErrors: mutable.Map[URI, Seq[Fetcher.Error]] = mutable.Map.empty
}

class RepoService(fetcher: RepoFetcher) {

  private def interval(uri: URI) =
    if (uri.getScheme == "rsync")
      ApplicationOptions.rsyncFetcherInterval
    else
      ApplicationOptions.rddpFetcherInterval

  private val locker = RepoService.locker

  def visitRepo(forceNewFetch: Boolean, validationStart: Instant)(uri: URI): Seq[Fetcher.Error] =
    fetchAndUpdateTime(uri, forceNewFetch, validationStart) {
      fetcher.fetchRepo(uri)
    }

  def lastFetchTime(uri: URI): Instant = RepoServiceStore.getLastFetchTime(uri)

  protected[models] def fetchAndUpdateTime(uri: URI, forceNewFetch: Boolean, validationStart: Instant)(fetch: => Seq[Fetcher.Error]): Seq[Fetcher.Error] =
    locker.locked(uri) {
      if (!haveRecentDataInStore(uri, validationStart, forceNewFetch)) {
        val errors = fetch
        RepoServiceErrors.lastErrors(uri) = errors
        if (!Option(errors).exists(_.exists(_.isInstanceOf[ConnectionError])))
          RepoServiceStore.updateLastFetchTime(uri, validationStart)
      }
      RepoServiceErrors.lastErrors.getOrElse(uri, Seq.empty)
    }

  def visitTrustAnchorCertificate(uri: URI, forceNewFetch: Boolean, validationStart: Instant) =
    fetchAndUpdateTime(uri, forceNewFetch, validationStart) {
      fetcher.fetchTrustAnchorCertificate(uri)
    }

  private def haveRecentDataInStore(uri: URI, validationTime: Instant, forceNewFetch: Boolean) =
    timeIsRecent(RepoServiceStore.getLastFetchTime(uri), interval(uri), validationTime, forceNewFetch)

  private[models] def timeIsRecent(lastFetchTime: Instant, minimalDuration: Duration, validationTime: Instant, forceNewFetch: Boolean) = {
    if (forceNewFetch)
      !lastFetchTime.isBefore(validationTime)
    else
      !lastFetchTime.plus(minimalDuration).isBefore(validationTime)
  }
}

object RepoService {
  val locker = new Locker
}
