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
package net.ripe.rpki.validator.rrdp

import java.net.URI
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate
import scala.collection.JavaConverters._
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext
import net.ripe.rpki.commons.crypto.crl.CrlLocator
import net.ripe.rpki.commons.validation.ValidationOptions
import net.ripe.rpki.commons.validation.ValidationResult

sealed trait RepositoryObjectStore {

  def rememberAll(updates: List[PublicationProtocolMessage]): Unit = {
    updates.foreach { update =>
      update match {
        case publish: Publish => {
          remember(publish.uri, publish.repositoryObject)
          if (publish.replaces.isDefined) { forget(publish.replaces.get) }
        }
        case withdraw: Withdraw => forget(withdraw.hash)
      }
    }
  }

  def remember(uri: URI, repoObject: CertificateRepositoryObject): Unit
  def forget(hash: ReferenceHash): Unit
  def retrieve(hash: ReferenceHash): Option[CertificateRepositoryObject]

  def retrieveLatestManifest(akiHash: ReferenceHash): Option[ManifestCms]
  def forgetManifest(mft: ManifestCms): Unit

}

class InMemoryRepositoryObjectStore extends RepositoryObjectStore {

  val objectMap: scala.collection.mutable.Map[ReferenceHash, CertificateRepositoryObject] = scala.collection.mutable.Map()
  val manifestMap: scala.collection.mutable.Map[ReferenceHash, List[ManifestCms]] = scala.collection.mutable.Map()

  override def remember(uri: URI, repoObject: CertificateRepositoryObject): Unit = {
    objectMap.put(ReferenceHash.fromBytes(repoObject.getEncoded()), repoObject)

    if (uri.toString.endsWith(".mft")) {
      val mft = repoObject.asInstanceOf[ManifestCms]
      val akiHash = ReferenceHash.fromBytes(mft.getCertificate().getAuthorityKeyIdentifier())

      manifestMap.get(akiHash) match {
        case Some(mfts) => manifestMap.put(akiHash, mfts :+ mft)
        case None => manifestMap.put(akiHash, List(mft))
      }
    }
  }

  override def forget(hash: ReferenceHash) = objectMap -= hash
  override def retrieve(hash: ReferenceHash): Option[CertificateRepositoryObject] = objectMap.get(hash)

  override def retrieveLatestManifest(akiHash: ReferenceHash): Option[ManifestCms] = manifestMap.get(akiHash).map(_.sortBy(_.getNumber).last)
  override def forgetManifest(mft: ManifestCms): Unit = {
    forget(ReferenceHash.fromBytes(mft.getEncoded))
    val akiHash = ReferenceHash.fromBytes(mft.getCertificate().getAuthorityKeyIdentifier())

    if (manifestMap.isDefinedAt(akiHash)) {
      val remainingForAki = manifestMap.get(akiHash).get.filterNot(_.equals(mft))
      if (!remainingForAki.isEmpty) {
        manifestMap.put(akiHash, remainingForAki)
      } else {
        manifestMap -= akiHash
      }
    }
  }


}