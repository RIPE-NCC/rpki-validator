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
package net.ripe.rpki.validator.models.validation

import java.math.BigInteger
import java.net.URI

import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsParser}
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.{X509ResourceCertificate, X509ResourceCertificateParser}
import net.ripe.rpki.commons.validation.ValidationResult
import net.ripe.rpki.validator.fetchers.{HttpFetcher, RsyncFetcher}
import net.ripe.rpki.validator.store.Storage

import scala.collection.JavaConversions._


trait Hashing {
  def getHash(bytes: Array[Byte]): Array[Byte] = ManifestCms.hashContents(bytes)

  def stringify(bytes: Array[Byte]) = bytes.map { b => String.format("%02X", new Integer(b & 0xff))}.mkString

  def stringToBytes(s: String) = new BigInteger(s, 16).toByteArray

  def equals(hashA: Array[Byte], hashB: Array[Byte]): Boolean = { hashA.deep == hashB.deep }
}

sealed trait RepositoryObject[T] extends Hashing {
  def url: String

  def aki: Array[Byte]

  def encoded: Array[Byte]

  def hash: Array[Byte] = getHash(encoded)

  def decoded: T
}

trait Parsing {

  def formatFailures(r: ValidationResult) = r.getFailuresForAllLocations.map {
    ch => s"[${ch.getKey}, status = ${ch.getStatus}, params = ${ch.getParams.mkString(" ")}]"
  }.mkString("\n")

  def parseOrReturnBroken[T](url: String, bytes: Array[Byte])(f: => Either[BrokenObject, T]) = try f catch {
    case e: Exception => Left(BrokenObject(url, bytes, e.getMessage))
  }
}

case class BrokenObject(url: String, bytes: Array[Byte], errorMessage: String) extends Hashing {
  def hash: Array[Byte] = getHash(bytes)
}

object CertificateObject extends Parsing {

  private def makeParser(url: String, bytes: Array[Byte]) = {
    val parser = new X509ResourceCertificateParser
    parser.parse(url, bytes)
    parser
  }

  def parse(url: String, bytes: Array[Byte]) = CertificateObject(url, makeParser(url, bytes).getCertificate)

  def tryParse(url: String, bytes: Array[Byte]) = parseOrReturnBroken(url, bytes) {
    val parser = makeParser(url, bytes)
    if (parser.isSuccess)
      Right(CertificateObject(url, parser.getCertificate))
    else
      Left(BrokenObject(url, bytes, formatFailures(parser.getValidationResult)))
  }
}


object ManifestObject extends Parsing {

  private def makeParser(url: String, bytes: Array[Byte]) = {
    val parser = new ManifestCmsParser
    parser.parse(url, bytes)
    parser
  }

  def parse(url: String, bytes: Array[Byte]) = ManifestObject(url, makeParser(url, bytes).getManifestCms)

  def tryParse(url: String, bytes: Array[Byte]) = {
    val parser = makeParser(url, bytes)
    if (parser.isSuccess)
      Right(ManifestObject(url, parser.getManifestCms))
    else
      Left(BrokenObject(url, bytes, formatFailures(parser.getValidationResult)))
  }
}

object CrlObject extends Parsing {

  def parse(url: String, bytes: Array[Byte]) = CrlObject(url, new X509Crl(bytes))

  def tryParse(url: String, bytes: Array[Byte]) = parseOrReturnBroken(url, bytes) {
    Right(parse(url, bytes))
  }
}

object RoaObject extends Parsing {

  def parse(url: String, bytes: Array[Byte]) = RoaObject(url, RoaCms.parseDerEncoded(bytes))

  def tryParse(url: String, bytes: Array[Byte]) = parseOrReturnBroken(url, bytes) {
    Right(parse(url, bytes))
  }
}

case class CertificateObject(override val url: String,
                             override val decoded: X509ResourceCertificate) extends RepositoryObject[X509ResourceCertificate] {

  def encoded = decoded.getEncoded
  def aki = decoded.getAuthorityKeyIdentifier
  def ski = decoded.getSubjectKeyIdentifier
}

case class ManifestObject(override val url: String,
                          override val decoded: ManifestCms) extends RepositoryObject[ManifestCms] {
  def encoded = decoded.getEncoded
  def aki = decoded.getCertificate.getAuthorityKeyIdentifier
}

case class CrlObject(override val url: String,
                     override val decoded: X509Crl) extends RepositoryObject[X509Crl] {
  def encoded = decoded.getEncoded
  def aki = decoded.getAuthorityKeyIdentifier
}

case class RoaObject(override val url: String,
                     override val decoded: RoaCms) extends RepositoryObject[RoaCms] {

  def aki = decoded.getCertificate.getAuthorityKeyIdentifier
  def encoded = decoded.getEncoded
}


class RepoFetcher(storage: Storage) {

  val rsyncUrlPool = scala.collection.mutable.Set[String]()
  val httpUrlPool = scala.collection.mutable.Set[String]()

  /**
   * It's the mapping of the form "localhost:8888/a/b/c =>
   *   [localhost:8888, localhost:8888/a, localhost:8888/a/b, localhost:8888/a/b/c]
   */
  private def chunked(uri: String) =
    uri.split("/").toSeq.foldLeft((Seq[Seq[String]](), Seq[String]())) {
      (accum, ch) => {
        val newLatest = accum._2 :+ ch
        (accum._1 :+ newLatest, newLatest)
      }
    }._1.map {
      _.mkString("","/","/")
    }

  private def checkRsyncPool(uri: URI)(f: => Seq[String]) = {
    val u = uri.toString.replaceAll("rsync://", "")
    if (!chunked(u).exists(rsyncUrlPool.contains)) {
      val result = f
      rsyncUrlPool.add(u)
      result
    } else Seq()
  }

  private def checkHttpPool(uri: URI)(f: => Seq[String]) = {
    val u = uri.toString
    if (!httpUrlPool.contains(u)) {
      val result = f
      httpUrlPool.add(u)
      result
    } else Seq()
  }

  def fetch(repoUri: URI): Seq[String] = {
    val (fetcher, fetchOnlyOnce) = repoUri.getScheme match {
      case "rsync" => (new RsyncFetcher, checkRsyncPool _)
      case "http" | "https" => (new HttpFetcher, checkHttpPool _)
      case _ => throw new Exception(s"No fetcher for the uri $repoUri")
    }

    fetchOnlyOnce(repoUri) {
      fetcher.fetchRepo(repoUri) {
        case Right(c: CertificateObject) => storage.storeCertificate(c)
        case Right(c: CrlObject) => storage.storeCrl(c)
        case Right(c: ManifestObject) => storage.storeManifest(c)
        case Right(c: RoaObject) => storage.storeRoa(c)
        case Left(b: BrokenObject) => storage.storeBroken(b)
      }
    }
  }
}
