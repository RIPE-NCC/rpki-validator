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
import java.sql.ResultSet
import javax.sql.DataSource

import net.ripe.rpki.validator.models.validation._
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.core.RowMapper
import scala.collection.JavaConversions._
import scala.collection.mutable
import scala.util.Try

trait Storage {

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
}

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  val template: NamedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource)

  override def storeCertificate(certificate: CertificateObject) =
    template.update(
      """INSERT INTO certificates(aki, ski, hash, url, encoded)
         SELECT :aki, :ski, :hash, :url, :encoded
         WHERE NOT EXISTS (
           SELECT * FROM certificates c
           WHERE c.url = :url
           AND  c.hash = :hash
         )
      """,
      Map("aki" -> stringify(certificate.aki),
        "ski" -> stringify(certificate.ski),
        "hash" -> stringify(certificate.hash),
        "url" -> certificate.url,
        "encoded" -> certificate.encoded))

  override def storeRoa(roa: RoaObject) = storeRepoObject(roa, "roa")

  override def storeManifest(manifest: ManifestObject) = storeRepoObject(manifest, "manifest")

  override def storeCrl(crl: CrlObject) = storeRepoObject(crl, "crl")

  private def storeRepoObject[T](obj: RepositoryObject[T], objType: String) = {
    template.update(
      """INSERT INTO repo_objects(aki, hash, url, encoded, object_type)
         SELECT :aki, :hash, :url, :encoded, :object_type
         WHERE NOT EXISTS (
           SELECT * FROM repo_objects ro
           WHERE ro.hash = :hash
           AND ro.url = :url
         )
      """,
      Map("aki" -> stringify(obj.aki),
        "hash" -> stringify(obj.hash),
        "url" -> obj.url,
        "encoded" -> obj.encoded,
        "object_type" -> objType))
  }

  override def storeBroken(broken: BrokenObject) = {
    template.update(
      """INSERT INTO broken_objects(hash, url, encoded, message)
         SELECT :hash, :url, :encoded, :message
         WHERE NOT EXISTS (
           SELECT * FROM broken_objects ro
           WHERE ro.url = :url
         )
      """,
      Map("hash" -> stringify(broken.hash),
        "url" -> broken.url,
        "encoded" -> broken.bytes,
        "message" -> broken.errorMessage))
  }

  override def getCertificate(url: String): Option[CertificateObject] =
    try {
      Option(
        template.queryForObject("SELECT url, encoded FROM certificates WHERE url = :url",
          Map("url" -> url),
          new RowMapper[CertificateObject] {
            override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(2))
          }
        )
      )
    } catch {
      case e: EmptyResultDataAccessException => None
    }

  override def getCertificates(aki: Array[Byte]): Seq[CertificateObject] =
    template.query("SELECT url, ski, encoded FROM certificates WHERE aki = :aki",
      Map("aki" -> stringify(aki)),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(3))
      }).toSeq

  def getCrls(aki: Array[Byte]) = getRepoObject[CrlObject](aki, "crl")(CrlObject.parse)

  def getManifests(aki: Array[Byte]) = getRepoObject[ManifestObject](aki, "manifest")(ManifestObject.parse)

  def getRoas(aki: Array[Byte]) = getRepoObject[RoaObject](aki, "roa")(RoaObject.parse)

  override def getBroken(url: String) = Try {
    template.queryForObject(
      "SELECT encoded, message FROM broken_objects WHERE url = :url",
      Map("url" -> url),
      new RowMapper[BrokenObject] {
        override def mapRow(rs: ResultSet, i: Int) = BrokenObject(url, rs.getBytes(1), rs.getString(2))
      })
  }.toOption

  override def getBroken = template.query(
    "SELECT url, encoded, message FROM broken_objects", Map[String, Object](),
    new RowMapper[BrokenObject] {
      override def mapRow(rs: ResultSet, i: Int) = BrokenObject(rs.getString(1), rs.getBytes(2), rs.getString(3))
    }).toSeq

  private def getRepoObject[T](aki: Array[Byte], objType: String)(mapper: (String, Array[Byte]) => T) =
    template.query("SELECT url, encoded FROM repo_objects WHERE aki = :aki AND object_type = :object_type",
      Map("aki" -> stringify(aki), "object_type" -> objType),
      new RowMapper[T] {
        override def mapRow(rs: ResultSet, i: Int) = mapper(rs.getString(1), rs.getBytes(2))
      }).toSeq

  def clear() = {
    for (t <- Seq("certificates", "repo_objects", "broken_objects"))
      template.update(s"TRUNCATE TABLE $t", Map[String, Object]())
  }
}

object DurableCaches {

  private val caches = mutable.Map[String, CacheStore]()

  def store(path: File) = {
    synchronized {
      val absolutePath = path.getAbsolutePath
      caches.get(absolutePath).fold({
        val c = new CacheStore(DataSources.DurableDataSource(path))
        caches += absolutePath -> c
        c
      })(identity)
    }
  }
}

