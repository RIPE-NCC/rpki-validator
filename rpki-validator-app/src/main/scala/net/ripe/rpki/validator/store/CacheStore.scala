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

import scala.language.existentials
import java.io.File
import java.sql.{ResultSet, Timestamp}
import javax.sql.DataSource

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.validator.lib.Locker
import net.ripe.rpki.validator.models.validation._
import org.joda.time.Instant
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.core.{JdbcTemplate, RowMapper}
import org.springframework.jdbc.datasource.DataSourceTransactionManager
import org.springframework.transaction.TransactionStatus
import org.springframework.transaction.support.{TransactionCallback, TransactionTemplate}

import scala.collection.JavaConversions._
import scala.util.Try

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  private val template = new NamedParameterJdbcTemplate(dataSource)
  private val tx = new DataSourceTransactionManager(dataSource)

  override def atomic[T](f: => T) = new TransactionTemplate(tx).execute(new TransactionCallback[T] {
    override def doInTransaction(transactionStatus: TransactionStatus) = f
  })

  private val roaObjectType = "roa"
  private val manifestObjectType = "mft"
  private val crlObjectType = "crl"
  private val certificateObjectType = "cer"

  private val deletionDelay = 2

  private val locker = new Locker

  override def storeCertificate(certificate: CertificateObject) = storeRepoObject(certificate, certificateObjectType)

  override def storeRoa(roa: RoaObject) = storeRepoObject(roa, roaObjectType)

  override def storeManifest(manifest: ManifestObject) = storeRepoObject(manifest, manifestObjectType)

  override def storeCrl(crl: CrlObject) = storeRepoObject(crl, crlObjectType)

  private def storeRepoObject[T <: CertificateRepositoryObject](obj: RepositoryObject[T], objType: String) =
    locker.locked(obj.url) {
      val params = Map("aki" -> stringify(obj.aki),
        "hash" -> stringify(obj.hash),
        "url" -> obj.url,
        "encoded" -> obj.encoded,
        "object_type" -> objType)

      template.update(
        """INSERT INTO repo_objects(aki, hash, url, encoded, object_type)
           SELECT :aki, :hash, :url, :encoded, :object_type
           WHERE NOT EXISTS (
             SELECT * FROM repo_objects
             WHERE hash = :hash
             AND   url  = :url
           )
        """, params)
    }

  override def getCertificate(url: String): Option[CertificateObject] = Try {
    template.queryForObject("SELECT url, encoded FROM repo_objects WHERE url = :url AND object_type = :object_type",
      Map("url" -> url, "object_type" -> certificateObjectType),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(2))
      }
    )
  }.toOption

  def getCrls(aki: Array[Byte]) = getRepoObject[CrlObject](aki, crlObjectType) { (url, bytes, validationTime) =>
    CrlObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  def getManifests(aki: Array[Byte]) = getRepoObject[ManifestObject](aki, manifestObjectType) { (url, bytes, validationTime) =>
    ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  private def getRepoObject[T](aki: Array[Byte], objType: String)(mapper: (String, Array[Byte], Option[Instant]) => T) =
    template.query(
      """SELECT url, encoded, validation_time
        FROM repo_objects
        WHERE aki = :aki AND object_type = :object_type""",
      Map("aki" -> stringify(aki), "object_type" -> objType),
      new RowMapper[T] {
        override def mapRow(rs: ResultSet, i: Int) = mapper(rs.getString(1), rs.getBytes(2), instant(rs.getTimestamp(3)))
      }).toSeq

  override def getObject(hash: String): Option[RepositoryObject.ROType] =
    Try {
      template.queryForObject(
        """SELECT encoded, validation_time, object_type, url
        FROM repo_objects
        WHERE hash = :hash""",
        Map("hash" -> hash),
        new RowMapper[RepositoryObject.ROType] {
          override def mapRow(rs: ResultSet, i: Int) = {
            val (bytes, validationTime, objType, url) = (rs.getBytes(1), instant(rs.getTimestamp(2)), rs.getString(3), rs.getString(4))
            objType match {
              case "cer" => CertificateObject.parse(url, bytes).copy(validationTime = validationTime)
              case "roa" => RoaObject.parse(url, bytes).copy(validationTime = validationTime)
              case "mft" => ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
              case "crl" => CrlObject.parse(url, bytes).copy(validationTime = validationTime)
            }
          }
        })
    }.toOption

  def clear() = {
    template.update(s"TRUNCATE TABLE repo_objects", Map.empty[String, Object])
  }

  def clearObjects(olderThan: Instant) = {
    val tt = timestamp(olderThan.toDateTime.minusHours(deletionDelay).toInstant)
    atomic {
      val i = template.update(s"DELETE FROM repo_objects WHERE validation_time < '$tt'", Map.empty[String, Object])
      info(s"Clear Old Objects -> $i object(s) older than $olderThan deleted from repo_objects")

      val j = template.update(s"DELETE FROM repo_objects WHERE validation_time IS NULL AND download_time < '$tt'", Map.empty[String, Object])
      info(s"Clear Old Objects -> $j object(s) downloaded 2 hours before $olderThan deleted from repo_objects")
    }
  }

  override def delete(url: String, hash: String) = locker.locked(url) {
    template.update(s"DELETE FROM repo_objects WHERE url = :url AND hash = :hash",
      Map("hash" -> hash, "url" -> url))
  }

  def updateValidationTimestamp(urls: Iterable[String], t: Instant) = {
    val tt = timestamp(t)
    // That has to be as fast as possible to prevent
    // other threads from being locked. That's why
    // we do all that dancing.
    val sqls = urls.grouped(99).map { group =>
      val inClause = group.map("'" + _ + "'").mkString("(", ",", ")")
      s"UPDATE repo_objects SET validation_time = '$tt' WHERE url IN $inClause"
    }

    if (sqls.nonEmpty) {
      atomic {
        new JdbcTemplate(dataSource).batchUpdate(sqls.toArray)
      }
    }
  }

  private def timestamp(timestamp: Instant)= new Timestamp(timestamp.getMillis)
  private def instant(d: java.util.Date) = Option(d).map(d => new Instant(d.getTime))
}

object DurableCaches extends SimpleSingletons[String, CacheStore]({
  path =>
    new CacheStore(DataSources.DurableDataSource(new File(path)))
}) {
  def apply(d: File) : CacheStore = this.apply(d.getAbsolutePath)
}
