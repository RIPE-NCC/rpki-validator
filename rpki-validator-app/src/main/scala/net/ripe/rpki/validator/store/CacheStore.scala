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

import java.io.File
import java.net.URI
import javax.sql.DataSource

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.models.validation._
import org.joda.time.Instant

import scala.concurrent.stm._
import scala.language.existentials
import scala.util.{Failure, Success, Try}

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  private val roaObjectType = "roa"
  private val manifestObjectType = "mft"
  private val crlObjectType = "crl"
  private val certificateObjectType = "cer"
  private val ghostbustersObjectType = "gbr"

  val deletionDelay = ApplicationOptions.removeOldObjectTimeoutInHours.toHours.toInt
  val hoursForBogusObjects: Int = 24

  override def storeCertificate(certificate: CertificateObject) = storeRepoObject(certificate, certificateObjectType)

  override def storeRoa(roa: RoaObject) = storeRepoObject(roa, roaObjectType)

  override def storeGhostbusters(ghostbusters: GhostbustersObject) =
    storeRepoObject(ghostbusters, ghostbustersObjectType)

  override def storeManifest(manifest: ManifestObject) = storeRepoObject(manifest, manifestObjectType)

  override def storeCrl(crl: CrlObject) = storeRepoObject(crl, crlObjectType)

  case class StoredObject(repoObject: RepositoryObject.ROType,
                          objType: String,
                          validationTime: Option[Instant] = None,
                          downloadTime: Instant = Instant.now())

  type StorePK = (String, Seq[Byte])

  val objects = new IndexedMap[StorePK, StoredObject]

  val byHash = objects.addIndex { (_, obj) =>
    Option(obj.repoObject.hash)
  }
  val byUrl = objects.addIndex { (_, obj) =>
    Option(obj.repoObject.url)
  }
  val byAki = objects.addIndex { (_, obj) =>
    Option(obj.repoObject.aki).map(_.toSeq)
  }

  def dump() = {
    objects.getAll.foreach(o => println(o))
  }

  private def storeRepoObject[T <: CertificateRepositoryObject](obj: RepositoryObject[T], objType: String) = {
    //logger.info(s"Putting ${obj.hash} ${StoredObject(obj, objType)}")
    objects.put(obj.url -> obj.hash, StoredObject(obj, objType))
  }

  override def getCertificates(url: String): Seq[CertificateObject] = {
    byUrl(url).values
      .withFilter(_.objType == certificateObjectType)
      .map(o => CertificateObject.parse(o.repoObject.url, o.repoObject.encoded))
      .toSeq
  }

  override def getManifests(aki: Seq[Byte]) =
    getRepoObject[ManifestObject](aki, manifestObjectType) { (url, bytes) =>
      ManifestObject.parse(url, bytes.toArray)
    }

  private def getRepoObject[T](aki: Seq[Byte], objType: String)(mapper: (String, Seq[Byte]) => T) = {
    byAki(aki).values.withFilter(_.objType == objType).map(o => mapper(o.repoObject.url, o.repoObject.encoded)).toSeq
  }

  override def getObjects(hash: Seq[Byte]): Seq[RepositoryObject.ROType] = {
    byHash(hash).values.flatMap(classifyObject).toSeq
  }

  def getAllObjects = {
    objects.getAll.flatMap(classifyObject).toSeq
  }

  private def classifyObject(obj: StoredObject): Seq[RepositoryObject.ROType] = {
    val (bytes, url) = (obj.repoObject.encoded, obj.repoObject.url)
    Try {
      obj.objType match {
        case "cer" => CertificateObject.parse(url, bytes)
        case "roa" => RoaObject.parse(url, bytes)
        case "mft" => ManifestObject.parse(url, bytes)
        case "crl" => CrlObject.parse(url, bytes)
        case "gbr" => GhostbustersObject.parse(url, bytes)
      }
    } match {
      case Success(goodObject) =>
        Seq(goodObject)
      case Failure(err) =>
        logger.error(err)
        Seq()
    }
  }

  def clear() = ???

  def clearObjects(baseTime: Instant) = {
    val thresholdTime = baseTime.toDateTime.minusHours(deletionDelay).toInstant

    val nrDeletedOutdated = atomic { implicit txn =>
      val toRemove = objects.getAll.filter(_.validationTime.exists(_.isBefore(thresholdTime)))

      toRemove.map { obj =>
        objects.remove(obj.repoObject.url -> obj.repoObject.hash).size
      }.sum
    }

    if (nrDeletedOutdated != 0)
      info(s"Clear old objects -> deleted $nrDeletedOutdated object(s) last time validated before $thresholdTime")

    val bogusObjectsDeadline = baseTime.toDateTime.minusHours(hoursForBogusObjects).toInstant

    val nrDeletedBogus = atomic { implicit txn =>
      val toRemove = objects.getAll.filter(_.validationTime.forall(_.isBefore(bogusObjectsDeadline)))

      toRemove.map { obj =>
        objects.remove(obj.repoObject.url -> obj.repoObject.hash).size
      }.sum
    }
    if (nrDeletedBogus != 0)
      info(
        s"Clear old objects -> deleted $nrDeletedBogus object(s) downloaded $hoursForBogusObjects hours " +
          s"before $baseTime and never validated")
  }

  override def delete(url: String, hash: String) = {
    parseBytes(hash).map { binaryHash =>
      objects.remove(url -> binaryHash)
    }
  }

  override def delete(uri: URI) = atomic { implicit txn =>
    val keysToDelete = byUrl(uri.toString).keys
    keysToDelete.foreach(objects.remove)
  }

  override def updateValidationTimestamp(hashes: Iterable[Seq[Byte]], validationTime: org.joda.time.Instant): Unit = {
    val count = atomic { implicit txn =>
      objects.getAll
        .withFilter(o => hashes.exists(_ == o.repoObject.hash))
        .map { o =>
          val updated = o.copy(validationTime = Option(validationTime))
          objects.put(o.repoObject.url -> o.repoObject.hash, updated)
        }
        .size
    }
    info(s"Updated validationTime for $count objects.")
  }

  override def cleanOutdated(validated: Iterable[(java.net.URI, Seq[Byte])]): Unit = {
    val counts = validated.groupBy(_._1).map {
      case (uri, hashes) =>
        atomic { implicit txn =>
          val toDelete = byUrl(uri.toString).values.filter(obj => !hashes.exists(_._2 == obj.repoObject.hash))
          toDelete.map { obj =>
            objects.remove(obj.repoObject.url -> obj.repoObject.hash).size
          }.sum
        }
    }
    val sum = counts.sum
    if (sum != 0) info(s"Clear old objects -> deleted $sum objects for which exists a valid alternative.")
  }
}

object DurableCaches
    extends SimpleSingletons[String, CacheStore]({ path =>
      new CacheStore(DataSources.DurableDataSource(new File(path)))
    }) {
  def apply(d: File): CacheStore = this.apply(d.getAbsolutePath)
}
