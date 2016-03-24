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

import java.net.URI

import net.ripe.rpki.validator.models.validation._

case class FetcherConfig(rsyncDir: String = "")

trait FetcherListener {
  def processObject(repoObj: RepositoryObject.ROType)
  def withdraw(url: URI, hash: String)
}

object Fetcher {
  case class Error(url: URI, message: String)
}

trait Fetcher extends Hashing {

  import net.ripe.rpki.validator.fetchers.Fetcher._

  def fetch(url: URI, process: FetcherListener): Seq[Error]

  protected def processObject(uri: URI, bytes: Array[Byte], fetcherListener: FetcherListener): Either[Error, Unit] = {
    def checkIfBroken[T](parsed: => Either[BrokenObject, T]) =
      parsed.left.map { bo =>
        Error(uri, "Could not parse object")
      }

    val uriStr = uri.toString
    tryTo(uri) {
      uriStr.takeRight(4).toLowerCase
    }.right.flatMap { extension =>
      val repoObject = extension match {
        case ".cer" => checkIfBroken(CertificateObject.tryParse(uriStr, bytes))
        case ".mft" => checkIfBroken(ManifestObject.tryParse(uriStr, bytes))
        case ".crl" => checkIfBroken(CrlObject.tryParse(uriStr, bytes))
        case ".roa" => checkIfBroken(RoaObject.tryParse(uriStr, bytes))
        case ".gbr" => checkIfBroken(GhostbustersObject.tryParse(uriStr, bytes))
        case _ =>
          Left(Error(uri, "Found unknown file $f"))
      }
      repoObject.right.map { ro =>
        fetcherListener.processObject(ro)
      }
    }
  }

  protected def tryTo[R](uri: URI)(f: => R) =
    try {
      Right(f)
    } catch {
      case e: Throwable => Left(Error(uri, e.getMessage))
    }
}

