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
import java.util.concurrent.Executors
import javax.sql.DataSource

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject
import net.ripe.rpki.validator.config.ApplicationOptions
import net.ripe.rpki.validator.models.RepoService
import net.ripe.rpki.validator.models.validation._
import org.joda.time.Instant
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate

import scala.collection.JavaConversions._
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.language.existentials
import scala.util.{Failure, Success, Try}

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  protected[store] val template = new NamedParameterJdbcTemplate(dataSource)

  private val roaObjectType = "roa"
  private val manifestObjectType = "mft"
  private val crlObjectType = "crl"
  private val certificateObjectType = "cer"
  private val ghostbustersObjectType = "gbr"

  val deletionDelay = ApplicationOptions.removeOldObjectTimeoutInHours.toHours.toInt

  override def storeCertificate(certificate: CertificateObject) = storeRepoObject(certificate, certificateObjectType)

  override def storeRoa(roa: RoaObject) = storeRepoObject(roa, roaObjectType)

  override def storeGhostbusters(ghostbusters: GhostbustersObject) = storeRepoObject(ghostbusters, ghostbustersObjectType)

  override def storeManifest(manifest: ManifestObject) = storeRepoObject(manifest, manifestObjectType)

  override def storeCrl(crl: CrlObject) = storeRepoObject(crl, crlObjectType)

  // run on separate thread pool to be sure there's always a thread to run DB operation
  val executionContext = ExecutionContext.fromExecutorService(Executors.newSingleThreadExecutor())
  def detached[T](block: => T) = Await.result(Future(block)(executionContext), 6.minutes)

  private def storeRepoObject[T <: CertificateRepositoryObject](obj: RepositoryObject[T], objType: String) =
    RepoService.locker.locked(obj.url) {
      detached {
        try {
          val params = Map("aki" -> stringify(obj.aki),
            "hash" -> stringify(obj.hash),
            "url" -> obj.url,
            "encoded" -> obj.encoded,
            "object_type" -> objType)

          val found = template.queryForObject(
            "SELECT COUNT(1) FROM repo_objects WHERE hash = :hash AND url = :url",
            params, classOf[Integer])

          if (found == 0) {
            template.update(
              """INSERT INTO repo_objects(aki, hash, url, encoded, object_type)
               VALUES(:aki, :hash, :url, :encoded, :object_type)""",
              params)
          }
        } catch {
          case e: Exception =>
            logger.error(s"An error occurred while inserting an object: " +
              s"url = ${obj.url}, hash = ${stringify(obj.hash)}", e)
            throw e
        }
      }
    }

  override def getCertificates(url: String): Seq[CertificateObject] = detached {
    template.query(
      """SELECT url, encoded FROM repo_objects
         WHERE url = :url AND object_type = :object_type
         ORDER BY download_time DESC
      """,
      Map("url" -> url, "object_type" -> certificateObjectType),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(2))
      }
    ).toSeq
  }

  def getManifests(aki: Array[Byte]) = getRepoObject[ManifestObject](aki, manifestObjectType) { (url, bytes, validationTime) =>
    ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
  }

  private def getRepoObject[T](aki: Array[Byte], objType: String)(mapper: (String, Array[Byte], Option[Instant]) => T) =
    detached {
      template.query(
        """SELECT url, encoded, validation_time
        FROM repo_objects
        WHERE aki = :aki AND object_type = :object_type""",
        Map("aki" -> stringify(aki), "object_type" -> objType),
        new RowMapper[T] {
          override def mapRow(rs: ResultSet, i: Int) = mapper(rs.getString(1), rs.getBytes(2), instant(rs.getTimestamp(3)))
        }).toSeq
    }

  override def getObjects(hash: String): Seq[RepositoryObject.ROType] =
    getAllObjectsBy(
      """SELECT encoded, validation_time, object_type, url
        FROM repo_objects
        WHERE hash = :hash""", Map("hash" -> hash))

  def getAllObjects = getAllObjectsBy("SELECT encoded, validation_time, object_type, url FROM repo_objects", Map())

  def getAllObjectsBy(query: String, params: Map[String, Object]): Seq[RepositoryObject.ROType] = detached {
    Try {
      template.query(query, params,
        new RowMapper[RepositoryObject.ROType] {
          override def mapRow(rs: ResultSet, i: Int) = {
            val (bytes, validationTime, objType, url) = (rs.getBytes(1), instant(rs.getTimestamp(2)), rs.getString(3), rs.getString(4))
            objType match {
              case "cer" => CertificateObject.parse(url, bytes).copy(validationTime = validationTime)
              case "roa" => RoaObject.parse(url, bytes).copy(validationTime = validationTime)
              case "mft" => ManifestObject.parse(url, bytes).copy(validationTime = validationTime)
              case "crl" => CrlObject.parse(url, bytes).copy(validationTime = validationTime)
              case "gbr" => GhostbustersObject.parse(url, bytes).copy(validationTime = validationTime)
            }
          }
        })
    } match {
      case Success(obj) => obj
      case Failure(err) =>
        logger.error(s"$err, parameters = $params")
        Seq()
    }
  }

  def clear() = detached {
    template.update(s"TRUNCATE TABLE repo_objects", Map.empty[String, Object])
  }

  def clearObjects(baseTime: Instant) = detached {
      val thresholdTime = baseTime.toDateTime.minusHours(deletionDelay).toInstant
      val tt = timestamp(thresholdTime)
      val i = template.update(s"DELETE FROM repo_objects WHERE validation_time < '$tt'", Map.empty[String, Object])
      if (i != 0) info(s"Clear old objects -> deleted $i object(s) last time validated before $thresholdTime")

      val hoursForBogusObjects: Int = 24
      val bogusObjectsDeadline = baseTime.toDateTime.minusHours(hoursForBogusObjects).toInstant
      val j = template.update(
        s"DELETE FROM repo_objects WHERE validation_time IS NULL AND download_time < '${timestamp(bogusObjectsDeadline)}'",
        Map.empty[String, Object])
      if (j != 0) info(s"Clear old objects -> deleted $j object(s) downloaded $hoursForBogusObjects hours before $baseTime and never validated")
  }

  override def delete(url: String, hash: String) = detached {
    template.update(s"DELETE FROM repo_objects WHERE url = :url AND hash = :hash",
      Map("hash" -> hash, "url" -> url))
  }

  override def delete(uri: URI) = detached {
    template.update(s"DELETE FROM repo_objects WHERE url = :url",
      Map("url" -> uri.toString))
  }

  override def updateValidationTimestamp(hashes: Iterable[Array[Byte]], t: Instant) = {
    val tt = timestamp(t)
    // That has to be as fast as possible to prevent
    // other threads from being locked. That's why
    // we do all that dancing.
    val sqls = hashes.map(stringify).grouped(99).map { group =>
      val inClause = group.map("'" + _ + "'").mkString("(", ",", ")")
      s"UPDATE repo_objects SET validation_time = '$tt' WHERE hash IN $inClause"
    }

    if (sqls.nonEmpty) {
      val counts = detached(template.getJdbcOperations.batchUpdate(sqls.toArray))
      info(s"Updated validationTime for ${counts.sum} objects.")
    }
  }

  private def timestamp(timestamp: Instant) = new Timestamp(timestamp.getMillis)
  private def instant(d: java.util.Date) = Option(d).map(d => new Instant(d.getTime))

  override def cleanOutdated(validated: Iterable[(URI, Array[Byte])]) = {
      val sqls = validated.groupBy(_._1).map { x =>
      val (uri, hashes) = x
      val inClause = hashes.map(p => "'" + stringify(p._2) + "'").mkString("(", ",", ")")
      s"DELETE FROM repo_objects WHERE url = '$uri' AND hash NOT IN $inClause"
    }
    if (sqls.nonEmpty) {
      val counts = template.getJdbcOperations.batchUpdate(sqls.toArray)
      val sum = counts.sum
      if (sum > 0) info(s"Clear old objects -> deleted $sum objects for which exists a valid alternative.")
    }
  }
}

object DurableCaches extends SimpleSingletons[String, CacheStore]({
  path =>
    new CacheStore(DataSources.DurableDataSource(new File(path)))
}) {
  def apply(d: File) : CacheStore = this.apply(d.getAbsolutePath)
}
