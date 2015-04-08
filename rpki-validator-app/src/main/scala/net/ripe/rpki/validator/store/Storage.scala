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

import net.ripe.rpki.validator.models.validation._
import org.joda.time.Instant

import scala.collection.mutable

trait Storage {

  def getObjects(url: String) : Seq[RepositoryObject[_]]

  def storeCertificate(certificate: CertificateObject)

  def storeManifest(manifest: ManifestObject)

  def storeCrl(crl: CrlObject)

  def storeRoa(Roa: RoaObject)

  def storeBroken(brokenObject: BrokenObject)

  def getCertificate(uri: String): Option[CertificateObject]

  def getCertificates(aki: Array[Byte]): Seq[CertificateObject]

  def getCrls(aki: Array[Byte]): Seq[CrlObject]

  def getRoas(aki: Array[Byte]): Seq[RoaObject]

  def getManifests(aki: Array[Byte]): Seq[ManifestObject]

  def getBroken(url: String): Option[BrokenObject]

  def getBroken: Seq[BrokenObject]

  def delete(url: String, hash: String)

  def delete(objs: Map[String, String])

  def clear()

  def atomic[T](f: => T): T

  def updateValidationTimestamp(urls: Iterable[String], t: Instant): Unit

  def updateValidationTimestamp(urls: Iterable[String]): Unit = updateValidationTimestamp(urls, Instant.now())
}

/**
 * Generic template for storage singletons.
 */
class Singletons[K, V](create: K => V) {
  private val caches = mutable.Map[K, V]()

  def apply(k: K): V = {
    synchronized {
      caches.get(k) match {
        case None =>
          val c = create(k)
          caches += (k -> c)
          c
        case Some(c) => c
      }
    }
  }
}
