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

  type Decoded = Either[String, T]

  def url: String

  def aki: Array[Byte]

  def encoded: Array[Byte]

  def hash: Array[Byte] = getHash(encoded)

  def decoded: T

  def tryDecode: Decoded

  def tryDecode(f: => Decoded) = try f catch {
    case e: Exception => Left(e.getMessage)
  }

  def formatFailures(r: ValidationResult) = r.getFailuresForAllLocations.map {
    ch => s"[${ch.getKey}, status = ${ch.getStatus}, params = ${ch.getParams.mkString(" ")}]"
  }.mkString("\n")

}

object CertificateObject {

  private def makeParser(url: String, bytes: Array[Byte]) = {
    val parser = new X509ResourceCertificateParser
    parser.parse(url, bytes)
    parser
  }

  def of(url: String, bytes: Array[Byte]): CertificateObject = {
    val certificate = makeParser(url, bytes).getCertificate
    CertificateObject(url, certificate.getAuthorityKeyIdentifier, bytes, certificate.getSubjectKeyIdentifier)
  }

}

case class CertificateObject(override val url: String,
                             override val aki: Array[Byte],
                             override val encoded: Array[Byte],
                             ski: Array[Byte]) extends RepositoryObject[X509ResourceCertificate] {
  def tryDecode = tryDecode {
    val parser = makeParser
    if (parser.isSuccess)
      Left(formatFailures(parser.getValidationResult))
    else
      Right(parser.getCertificate)
  }

  def decoded = makeParser.getCertificate

  private def makeParser = {
    val parser = new X509ResourceCertificateParser
    parser.parse(url, encoded)
    parser
  }
}

case class ManifestObject(override val url: String,
                          override val aki: Array[Byte],
                          override val encoded: Array[Byte]) extends RepositoryObject[ManifestCms] {

  def tryDecode = tryDecode {
    val parser: ManifestCmsParser = makeParser
    if (parser.isSuccess)
      Right(parser.getManifestCms)
    else
      Left(formatFailures(parser.getValidationResult))
  }

  def decoded = makeParser.getManifestCms

  private def makeParser: ManifestCmsParser = {
    val parser = new ManifestCmsParser
    parser.parse(url, encoded)
    parser
  }
}

case class CrlObject(override val url: String,
                     override val aki: Array[Byte],
                     override val encoded: Array[Byte]) extends RepositoryObject[X509Crl] {
  def decoded = new X509Crl(encoded)

  def tryDecode = tryDecode(Right(decoded))
}

case class RoaObject(override val url: String,
                     override val aki: Array[Byte],
                     override val encoded: Array[Byte]) extends RepositoryObject[RoaCms] {
  def decoded = RoaCms.parseDerEncoded(encoded)

  def tryDecode = tryDecode(Right(decoded))
}


class RepoFetcher(storage: Storage) {

  def fetch(repoUri: URI) = {
    val fetcher = repoUri.getScheme match {
      case "rsync" => new RsyncFetcher
      case "http" | "https" => new HttpFetcher
      case _ => throw new Exception(s"No fetcher for the uri $repoUri")
    }

    fetcher.fetchRepo(repoUri, {
      case c: CertificateObject => storage.storeCertificate(c)
      case c: CrlObject => storage.storeCrl(c)
      case m: ManifestObject => storage.storeManifest(m)
      case r: RoaObject => storage.storeRoa(r)
    })
  }
}
