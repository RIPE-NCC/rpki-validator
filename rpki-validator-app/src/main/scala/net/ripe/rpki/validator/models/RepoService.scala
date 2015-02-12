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

import net.ripe.rpki.validator.fetchers.Fetcher
import net.ripe.rpki.validator.lib.Locker
import net.ripe.rpki.validator.models.validation.RepoFetcher
import net.ripe.rpki.validator.store.RepoServiceStore
import org.joda.time.{Duration, Instant}

class RepoService(fetcher: RepoFetcher) {
  val UPDATE_INTERVAL = Duration.standardMinutes(5) //TODO

  private val locker = RepoService.locker

  def visitRepo(uri: URI): Seq[Fetcher.Error] = fetchAndUpdateTime(uri) {
    fetcher.fetch(uri)
  }

  protected[models] def fetchAndUpdateTime(uri: URI)(block: => Seq[Fetcher.Error]): Seq[Fetcher.Error] =
    locker.locked(uri) {
      if (haveRecentDataInStore(uri)) Seq()
      else {
        val fetchTime = Instant.now()
        val result = block
        RepoServiceStore.updateLastFetchTime(uri, fetchTime)
        result
      }
    }

  def visitObject(uri: URI) = fetchAndUpdateTime(uri) {
    fetcher.fetchObject(uri)
  }

  private def haveRecentDataInStore(uri: URI) =
    timeIsRecent(RepoServiceStore.getLastFetchTime(uri), UPDATE_INTERVAL)

  private[models] def timeIsRecent(dateTime: Instant, duration: Duration) = dateTime.plus(duration).isAfterNow
}

object RepoService {
  val locker = new Locker
}