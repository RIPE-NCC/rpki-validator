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

import java.io.{File, PrintWriter}
import java.net.URI
import java.nio.file.Files

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser
import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.models.validation._
import org.apache.log4j.Logger

import scala.collection.JavaConversions._

trait Fetcher {
  type Callback = Either[BrokenObject, RepositoryObject[_]] => Unit
  def fetchRepo(uri: URI, process: Callback)
}

class RsyncFetcher extends Fetcher {

  private val logger: Logger = Logger.getLogger(classOf[RsyncFetcher])

  private val OPTIONS = Seq("--update", "--times", "--copy-links", "--recursive")

  private def walkTree[T](d: File)(f: File => Unit): Unit = {
    if (d.isDirectory) {
      d.listFiles.foreach(walkTree(_)(f))
    } else f(d)
  }

  private[this] def withRsyncDir[T](uri: URI)(f: File => T) = {
    def uriToPath = uri.toString.replaceAll("rsync://", "")
    def destDir = {
      val rsyncPath = new File(ApplicationOptions.rsyncDirLocation + "/" + uriToPath)
      if (!rsyncPath.exists) {
        rsyncPath.mkdirs
      }
      rsyncPath
    }

    f(destDir)
  }

  override def fetchRepo(uri: URI, process: Callback) = withRsyncDir(uri) {
    tmpDir =>
      logger.info(s"Downloading the repository $uri to ${tmpDir.getAbsolutePath}")
      val r = new Rsync(uri.toString, tmpDir.getAbsolutePath)
      r.addOptions(OPTIONS)
      try {
        r.execute match {
          case 0 => Right(readObjects(tmpDir, uri, process))
          case code => Left( s"""Returned code: $code, stderr: ${r.getErrorLines.mkString("\n")}""")
        }
      } catch {
        case e: Exception => Left( s"""Failed with exception, ${e.getMessage}""")
      }
  }


  def readObjects(tmpRoot: File, repoUri: URI, process: Callback) = {

    val replacement = {
      val s = repoUri.toString
      if (s.endsWith("/")) s.dropRight(1) else s
    }

    def rsyncUrl(f: File) =
      f.getAbsolutePath.replaceAll(tmpRoot.getAbsolutePath, replacement)

    val pw = new PrintWriter(new File("repo.log"))
    walkTree(tmpRoot) {
      f =>
        f.getName.takeRight(3) match {
          case "cer" => process(CertificateObject.tryParse(rsyncUrl(f), readFile(f)))
          case "mft" => process(ManifestObject.tryParse(rsyncUrl(f), readFile(f)))
          case "crl" => process(CrlObject.tryParse(rsyncUrl(f), readFile(f)))
          case "roa" => process(RoaObject.tryParse(rsyncUrl(f), readFile(f)))
          case _ =>
            logger.info(s"Found useless file $f")
        }
    }
  }

  def hashToString(bytes: Array[Byte]) = bytes.map { b => String.format("%02X", new Integer(b & 0xff))}.mkString

  private def readFile(f: File) = Files.readAllBytes(f.toPath)

}

class HttpFetcher extends Fetcher {
  override def fetchRepo(uri: URI, process: Callback): Unit = ???
}
