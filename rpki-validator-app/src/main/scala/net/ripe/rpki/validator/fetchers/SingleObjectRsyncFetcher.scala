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

import java.io.File
import java.net.URI

import grizzled.slf4j.Logging

class SingleObjectRsyncFetcher(config: FetcherConfig) extends Fetcher with RsyncSupport with Logging {

  def fetch(uri: URI, fetcherListener: FetcherListener): Seq[Fetcher.Error] = {

    val (fullPath, dirPath) = {
      val path = uri.toString.replaceAll("rsync://", "")
      val lastSlashIndex = path.lastIndexOf("/")
      (path, path.dropRight(path.length - lastSlashIndex))
    }

    def destDir = {
      val rsyncPath = new File(config.rsyncDir + "/" + dirPath)
      if (!rsyncPath.exists) {
        rsyncPath.mkdirs
      }
      rsyncPath
    }

    val error = for {
      error <- rsync(uri, destDir).toLeft(()).right
      bytes <- readFile(new File(config.rsyncDir + "/" + fullPath)).right
      processResult <- processObject(uri, bytes, fetcherListener).right
    } yield processResult

    error.left.toSeq
  }


  override def options: Seq[String] = Seq("--update", "--times", "--copy-links")
}
