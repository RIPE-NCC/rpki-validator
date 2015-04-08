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
import java.sql.{ResultSet, Timestamp}
import java.util
import javax.sql.DataSource

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.validator.lib.Locker
import net.ripe.rpki.validator.models.validation._
import org.joda.time.Instant
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.core.{JdbcTemplate, RowMapper}
import org.springframework.jdbc.datasource.DataSourceTransactionManager
import org.springframework.transaction.TransactionStatus
import org.springframework.transaction.support.{TransactionCallback, TransactionTemplate}

import scala.collection.JavaConversions._
import scala.collection.immutable
import scala.util.Try

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  private val template = new NamedParameterJdbcTemplate(dataSource)
  private val tx = new DataSourceTransactionManager(dataSource)

  override def atomic[T](f: => T) = new TransactionTemplate(tx).execute(new TransactionCallback[T] {
    override def doInTransaction(transactionStatus: TransactionStatus) = f
  })

  private val roaObjectType = "roa"
  private val manifestObjectType = "manifest"
  private val crlObjectType = "crl"

  private val locker = new Locker

  override def storeCertificate(certificate: CertificateObject) =
    locker.locked(certificate.url) {
      val params = Map(
        "aki" -> stringify(certificate.aki),
        "ski" -> stringify(certificate.ski),
        "hash" -> stringify(certificate.hash),
        "url" -> certificate.url,
        "encoded" -> certificate.encoded)

      atomic {
        val updateCount = template.update(
          """UPDATE certificates SET
             hash = :hash,
             encoded = :encoded
           WHERE hash = :hash
           AND   url = :url
          """, params)

        if (updateCount == 0) {
          template.update(
            """INSERT INTO certificates(aki, ski, hash, url, encoded)
             VALUES (:aki, :ski, :hash, :url, :encoded)
            """, params)
        }
      }
    }


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

      atomic {
        val updateCount = template.update(
          """UPDATE repo_objects SET
             hash = :hash,
             object_type = :object_type,
             encoded = :encoded
           WHERE hash = :hash
           AND   url = :url
          """, params)

        if (updateCount == 0) {
          template.update(
            """INSERT INTO repo_objects(aki, hash, url, encoded, object_type)
               VALUES (:aki, :hash, :url, :encoded, :object_type)
            """, params)
        }
      }
    }

  override def storeBroken(broken: BrokenObject) =
    locker.locked(broken.url) {
      val params = Map("hash" -> stringify(broken.hash),
        "url" -> broken.url,
        "encoded" -> broken.bytes,
        "message" -> broken.errorMessage)

      atomic {
        val updateCount = template.update(
          """UPDATE broken_objects SET
             hash = :hash,
             encoded = :encoded,
             message = :message
           WHERE url = :url
          """, params)

        if (updateCount == 0) {
          template.update(
            """INSERT INTO broken_objects(hash, url, encoded, message)
             VALUES( :hash, :url, :encoded, :message)
            """, params)
        }
      }
    }

  override def getCertificate(url: String): Option[CertificateObject] = Try {
    template.queryForObject("SELECT url, encoded FROM certificates WHERE url = :url",
      Map("url" -> url),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(2))
      }
    )
  }.toOption

  override def getCertificates(aki: Array[Byte]): Seq[CertificateObject] =
    template.query(
      """SELECT url, ski, encoded, validation_time
        FROM certificates WHERE aki = :aki""",
      Map("aki" -> stringify(aki)),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(3)).
          copy(validationTime = instant(rs.getTimestamp(4)))
      }).toSeq

  def getCrls(aki: Array[Byte]) = getRepoObject[CrlObject](aki, crlObjectType) { (url, bytes, validationTime) =>
    CrlObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  def getManifests(aki: Array[Byte]) = getRepoObject[ManifestObject](aki, manifestObjectType) { (url, bytes, validationTime) =>
    ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  def getRoas(aki: Array[Byte]) = getRepoObject[RoaObject](aki, roaObjectType) { (url, bytes, validationTime) =>
    RoaObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  override def getBroken(url: String) = Try {
    template.queryForObject(
      "SELECT encoded, message FROM broken_objects WHERE url = :url",
      Map("url" -> url),
      new RowMapper[BrokenObject] {
        override def mapRow(rs: ResultSet, i: Int) = BrokenObject(url, rs.getBytes(1), rs.getString(2))
      })
  }.toOption

  override def getBroken = template.query(
    "SELECT url, encoded, message FROM broken_objects", Map.empty[String, Object],
    new RowMapper[BrokenObject] {
      override def mapRow(rs: ResultSet, i: Int) = BrokenObject(rs.getString(1), rs.getBytes(2), rs.getString(3))
    }).toSeq


  private def getRepoObject[T](aki: Array[Byte], objType: String)(mapper: (String, Array[Byte], Option[Instant]) => T) =
    template.query(
      """SELECT url, encoded, validation_time
        FROM repo_objects
        WHERE aki = :aki AND object_type = :object_type""",
      Map("aki" -> stringify(aki), "object_type" -> objType),
      new RowMapper[T] {
        override def mapRow(rs: ResultSet, i: Int) = mapper(rs.getString(1), rs.getBytes(2), instant(rs.getTimestamp(3)))
      }).toSeq

  override def getObjects(url: String): Seq[RepositoryObject[_]] = {
    val objects = template.query(
      """SELECT encoded, validation_time, object_type
        FROM repo_objects
        WHERE url = :url""",
      Map("url" -> url),
      new RowMapper[RepositoryObject[_]] {
        override def mapRow(rs: ResultSet, i: Int) = {
          val (bytes, validationTime, objType) = (rs.getBytes(1), instant(rs.getTimestamp(2)), rs.getString(3))
          objType match {
            case "roa" => RoaObject.parse(url, bytes).copy(validationTime = validationTime)
            case "manifest" => ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
            case "crl" => CrlObject.parse(url, bytes).copy(validationTime = validationTime)
          }
        }
      })

    val certificates = template.query(
      """SELECT encoded, validation_time
        FROM certificates
        WHERE url = :url""",
      Map("url" -> url),
      new RowMapper[RepositoryObject[_]] {
        override def mapRow(rs: ResultSet, i: Int) = {
          val (bytes, validationTime) = (rs.getBytes(1), instant(rs.getTimestamp(2)))
          CertificateObject.parse(url, bytes).copy(validationTime = validationTime)
        }
      })

    objects ++ certificates
  }

  def clear() = {
    for (t <- Seq("certificates", "repo_objects", "broken_objects"))
      template.update(s"TRUNCATE TABLE $t", Map.empty[String, Object])
  }

  override def delete(url: String, hash: String) = locker.locked(url) {
    tableName(url).foreach { t =>
      template.update(s"DELETE FROM $t WHERE url = :url AND hash = :hash",
        Map("hash" -> hash, "url" -> url))
    }
  }

  override def delete(objs: Map[String, String]) = {
    val sqls = objs.groupBy(kv => tableName(kv._1)).flatMap { x =>
      val (tableOption, tableObjects) = x
      tableOption.map { table =>
        tableObjects.grouped(99).map { tobj =>
          val condition = tobj.map(t => s"(url = '${t._1}' AND hash = '${t._2}')").mkString("(", " OR ", ")")
          s"DELETE FROM $table WHERE $condition"
        }
      }.getOrElse(Iterator.empty)
    }

    if (sqls.nonEmpty) {
      atomic {
        new JdbcTemplate(dataSource).batchUpdate(sqls.toArray)
      }
    }
  }

  def tableName(uri: String): Option[String] =
    uri.takeRight(3).toLowerCase match {
      case "cer" => Some("certificates")
      case "mft" | "crl" | "roa" => Some("repo_objects")
      case _ => None
    }

  def updateValidationTimestamp(urls: Iterable[String], t: Instant) = {
    val tt = timestamp(t)
    // That has to be as fast as possible to prevent
    // other threads from being locked. That's why
    // we do all that dancing.
    val sqls = urls.groupBy(tableName).flatMap { p =>
      val (tableOption, tableUrls) = p
      tableOption.map { table =>
        tableUrls.grouped(99).map { group =>
          val inClause = group.map("'" + _ + "'").mkString("(", ",", ")")
          s"UPDATE $table SET validation_time = '$tt' WHERE url IN $inClause"
        }
      }.getOrElse(Iterator.empty)
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

object DurableCaches extends Singletons[String, CacheStore]({
  path =>
    new CacheStore(DataSources.DurableDataSource(new File(path)))
}) {
  def apply(d: File) : CacheStore = this.apply(d.getAbsolutePath)
}
