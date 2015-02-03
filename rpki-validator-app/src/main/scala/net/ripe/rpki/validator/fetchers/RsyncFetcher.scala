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
import java.nio.file.Files

import net.ripe.rpki.commons.rsync.Rsync
import org.apache.log4j.Logger

import scala.collection.JavaConversions._

class RsyncFetcher(config: FetcherConfig) extends Fetcher {

  import net.ripe.rpki.validator.fetchers.Fetcher._

  private val logger: Logger = Logger.getLogger(classOf[RsyncFetcher])

  private val OPTIONS = Seq("--update", "--times", "--copy-links", "--recursive", "--delete")

  private def walkTree[T1, T2](d: File)(f: File => Either[T1, T2]): Seq[T1] = {
    if (d.isDirectory) {
      d.listFiles.map(walkTree(_)(f)).toSeq.flatten
    } else f(d).fold(Seq(_), { _ => Seq() })
  }

  private[this] def withRsyncDir[T](url: URI)(f: File => T) = {
    def urlToPath = url.toString.replaceAll("rsync://", "")
    def destDir = {
      val rsyncPath = new File(config.rsyncDir + "/" + urlToPath)
      if (!rsyncPath.exists) {
        rsyncPath.mkdirs
      }
      rsyncPath
    }

    f(destDir)
  }

  def rsyncMethod(url: URI, destDir: File): Option[Error] = {
    val r = new Rsync(url.toString, destDir.getAbsolutePath)
    r.addOptions(OPTIONS)
    try {
      r.execute match {
        case 0 => None
        case code => Some(Error(url, s"""Returned code: $code, stderr: ${r.getErrorLines.mkString("\n")}"""))
      }
    } catch {
      case e: Exception => Some(Error(url, s"""Failed with exception, ${e.getMessage}"""))
    }
  }

  override def fetchRepo(url: URI, fetcherListener: FetcherListener): Seq[Error] =
    fetchRepo(url, rsyncMethod, fetcherListener)

  def fetchRepo(url: URI, method: (URI, File) => Option[Error], fetcherListener: FetcherListener): Seq[Error] = withRsyncDir(url) {
    destDir =>
      logger.info(s"Downloading the repository $url to ${destDir.getAbsolutePath}")
      method(url, destDir).toSeq ++ readObjects(destDir, url, fetcherListener)
  }

  def readObjects(tmpRoot: File, repoUrl: URI, fetcherListener: FetcherListener): Seq[Error] = {
    val replacement = {
      val s = repoUrl.toString
      if (s.endsWith("/")) s.dropRight(1) else s
    }

    def rsyncUrl(f: File) =
      new URI(if (replacement.endsWith(f.getName))
        replacement
      else
        f.getAbsolutePath.replaceAll(tmpRoot.getAbsolutePath, replacement))

    walkTree(tmpRoot) { file =>
      processObject(rsyncUrl(file), readFile(file), fetcherListener)
    }
  }

  private def readFile(f: File) = Files.readAllBytes(f.toPath)
}

