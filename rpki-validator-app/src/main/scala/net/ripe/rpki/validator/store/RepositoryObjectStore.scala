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
package net.ripe.rpki.validator
package store

import java.net.URI
import java.sql.ResultSet
import org.apache.commons.codec.binary.Base64
import org.apache.commons.dbcp.BasicDataSource
import org.joda.time.DateTime
import org.springframework.dao.DuplicateKeyException
import org.springframework.dao.EmptyResultDataAccessException
import org.springframework.jdbc.core.RowMapper
import org.springframework.jdbc.core.JdbcTemplate
import com.googlecode.flyway.core.Flyway
import akka.util.ByteString
import javax.sql.DataSource
import models.StoredRepositoryObject
import org.joda.time.DateTimeZone

/**
 * Used to store/retrieve consistent sets of rpki objects seen for certificate authorities
 */
class RepositoryObjectStore(datasource: DataSource) {

  val template: JdbcTemplate = new JdbcTemplate(datasource)

  def put(retrievedObject: StoredRepositoryObject): Unit = {
    val updateOrder: java.lang.Long = template.queryForLong("SELECT NEXTVAL('update_order_seq')")
    try {
      template.update("insert into retrieved_objects (hash, uri, encoded_object, expires, update_order) values (?, ?, ?, ?, ?)",
        Base64.encodeBase64String(retrievedObject.hash.toArray),
        retrievedObject.uri.toString,
        Base64.encodeBase64String(retrievedObject.binaryObject.toArray),
        new java.sql.Timestamp(retrievedObject.expires.getMillis),
        updateOrder)
    } catch {
      case e: DuplicateKeyException =>
        // Object already exists, update the last seen time only.
        template.update("update retrieved_objects set update_order = ? where hash = ?",
          updateOrder,
          Base64.encodeBase64String(retrievedObject.hash.toArray))
    }
  }

  def put(retrievedObjects: Seq[StoredRepositoryObject]): Unit = {
    retrievedObjects.foreach(put(_))
  }

  def purgeExpired(maxStaleDays: Int = 0): Unit = {
    val mustBeValidAfter = new DateTime().minusDays(maxStaleDays)
    template.update("delete from retrieved_objects where expires < ?", new java.sql.Timestamp(mustBeValidAfter.getMillis))
  }

  def clear(): Unit = {
    template.update("truncate table retrieved_objects")
  }

  def getLatestByUrl(url: URI) = {
    val selectString = "select * from retrieved_objects where uri = ? order by update_order desc limit 1"
    val selectArgs = Array[Object](url.toString)
    getOptionalResult(selectString, selectArgs)
  }

  def getByHash(hash: Array[Byte]) = {
    val encodedHash = Base64.encodeBase64String(hash)
    val selectString = "select * from retrieved_objects where hash = ?"
    val selectArgs = Array[Object](encodedHash)
    getOptionalResult(selectString, selectArgs)
  }

  private def getOptionalResult(selectString: String, selectArgs: Array[Object]): Option[StoredRepositoryObject] = {
    try {
      Some(template.queryForObject(selectString, selectArgs, new StoredObjectMapper()))
    } catch {
      case e: EmptyResultDataAccessException => None
    }
  }

  private class StoredObjectMapper extends RowMapper[StoredRepositoryObject] {
    override def mapRow(rs: ResultSet, rowNum: Int) = {
      StoredRepositoryObject(
        hash = ByteString(Base64.decodeBase64(rs.getString("hash"))),
        uri = URI.create(rs.getString("uri")),
        binaryObject = ByteString(Base64.decodeBase64(rs.getString("encoded_object"))),
        expires = new DateTime(rs.getTimestamp("expires")).withZone(DateTimeZone.UTC))
    }
  }

}

object DataSources {
  /**
   * Store data on disk.
   */
  lazy val DurableDataSource = {
    val result = new BasicDataSource
    result.setUrl("jdbc:h2:data/rpki-objects")
    result.setDriverClassName("org.h2.Driver")
    result.setDefaultAutoCommit(true)
    migrate(result)
    result
  }

  /**
   * For unit testing
   */
  lazy val InMemoryDataSource = {
    val result = new BasicDataSource
    result.setUrl("jdbc:h2:mem:rpki-objects")
    result.setDriverClassName("org.h2.Driver")
    result.setDefaultAutoCommit(true)
    migrate(result)
    result
  }

  private def migrate(dataSource: DataSource) {
    val flyway = new Flyway
    flyway.setDataSource(dataSource)
    flyway.setBaseDir("/db/objectstore/migration")
    flyway.setBasePackage("net.ripe.rpki.validator.store.migration")
    flyway.migrate
  }
}
