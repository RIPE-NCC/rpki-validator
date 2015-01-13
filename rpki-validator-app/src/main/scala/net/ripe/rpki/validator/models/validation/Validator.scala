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

import java.net.URI

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import net.ripe.rpki.validator.fetchers.{HttpFetcher, RsyncFetcher, Fetcher}

import scala.language.reflectiveCalls

sealed trait RepositoryObject {
  def uri: String

  def hash: Array[Byte]
}

case class CertificateObject(override val uri: String, override val hash: Array[Byte], certificate: X509ResourceCertificate) extends RepositoryObject

case class ManifestObject(override val uri: String, override val hash: Array[Byte], manifest: ManifestCms) extends RepositoryObject

case class CrlObject(override val uri: String, override val hash: Array[Byte], crl: X509Crl) extends RepositoryObject

case class RoaObject(override val uri: String, override val hash: Array[Byte], roa: RoaCms) extends RepositoryObject


class Validator(repoUri: URI, storage: Storage) {

  val fetcher: Fetcher = repoUri.getScheme match {
    case "rsync" => new RsyncFetcher
    case "http" | "https" => new HttpFetcher
    case _ => throw new Exception(s"No fetcher for the uri $repoUri")
  }

  def fetchAll(certificate: CertificateObject) = {
    fetcher.fetchRepo(repoUri, {
      case c@CertificateObject(uri, hash, cert) => storage.storeCertificate(c)
      case c@CrlObject(uri, hash, crl) => storage.storeCrl(c)
      case m@ManifestObject(uri, hash, manifest) => storage.storeManifest(m)
      case r@RoaObject(uri, hash, manifest) => storage.storeRoa(r)
    })
  }

  def validate(certificate: CertificateObject) = {
    val prefetched = fetchAll(certificate)
  }

}

trait Storage {

  def storeCertificate(certificate: CertificateObject)

  def storeManifest(manifest: ManifestObject)

  def storeCrl(crl: CrlObject)

  def storeRoa(Roa: RoaObject)

}
