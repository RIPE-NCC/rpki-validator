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

import org.joda.time.Instant

object RepoServiceStore {
  var times = Map[String, Map[String, Instant]]()

  @inline
  private def norm(uri: URI) = {
    val u = uri.toString
    if (u.endsWith("/")) u else u + "/"
  }

  def getLastFetchTime(uri: URI, tag: String): Instant = {
    lazy val default = new Instant().withMillis(0)
    val instants = times.filterKeys(norm(uri).startsWith).values
    if (instants.isEmpty) default
    else {
      val is = instants.map(_.get(tag)).collect { case Some(i) => i }
      if (is.isEmpty) default
      else is.maxBy(_.getMillis)
    }
  }

  def updateLastFetchTime(uri: URI, tag: String, instant: Instant) = synchronized {
    val u = norm(uri)
    val mm = times.get(u) match {
      case None => Map(tag -> instant)
      case Some(m) => m ++ Map(tag -> instant)
    }
    times = times ++ Map(u -> mm)
  }
}