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

import models.RetrievedRepositoryObject
import org.apache.commons.dbcp.BasicDataSource
import com.googlecode.flyway.core.dbsupport.h2.H2JdbcTemplate
import java.sql.Connection
import org.h2.jdbc.JdbcConnection
import com.googlecode.flyway.core.Flyway
import com.googlecode.flyway.core.validation.ValidationMode
import javax.sql.DataSource
import java.net.URI
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.jdbc.core.RowMapper
import java.sql.ResultSet
import net.ripe.rpki.validator.models.RetrievedRepositoryObject
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory
import org.springframework.dao.IncorrectResultSizeDataAccessException
import org.springframework.dao.DuplicateKeyException

trait DbMigrations {

  def getDataSource: DataSource
  def getSqlMigrationsDir: String
  def getCodeMigrationsPackage: String

  private val flyway = new Flyway
  flyway.setDataSource(getDataSource)
  flyway.setBaseDir(getSqlMigrationsDir)
  flyway.setBasePackage(getCodeMigrationsPackage)
  flyway.migrate
}

/**
 * Used to store/retrieve consistent sets of rpki objects seen for certificate authorities
 */
class RepositoryObjectStore(datasource: DataSource) extends DbMigrations {

  override def getDataSource = datasource
  override def getSqlMigrationsDir = "/db/objectstore/migration"
  override def getCodeMigrationsPackage = "net.ripe.rpki.validator.store.migration"

  val template: JdbcTemplate = new JdbcTemplate(datasource)

  def put(retrievedObject: RetrievedRepositoryObject): Unit = {
    try {
      template.update("insert into retrieved_objects (hash, url, encoded_object) values(?,?,?)", retrievedObject.encodedHash, retrievedObject.url.toString, retrievedObject.encodedObject)
    } catch {
      case e: DuplicateKeyException => // object already exists, ignore this so that putting is idempotent
    }
  }

  def put(retrievedObjects: Seq[RetrievedRepositoryObject]): Unit = {
    retrievedObjects.foreach(put(_))
  }

  def clear(): Unit = {
    template.update("truncate table retrieved_objects")
  }

  def retrieveByUrl(url: URI) = {
    val selectString = "select * from retrieved_objects where url = ?"
    val selectArgs = Array[Object](url.toString)
    getOptionalResult(selectString, selectArgs)
  }

  def retrieveByHash(encodedHash: String) = {
    val selectString = "select * from retrieved_objects where hash = ?"
    val selectArgs = Array[Object](encodedHash)
    getOptionalResult(selectString, selectArgs)
  }

  private def getOptionalResult(selectString: String, selectArgs: Array[Object]): Option[RetrievedRepositoryObject] = {
    try {
      Some(template.queryForObject(selectString, selectArgs, new RetrievedObjectMapper()))
    } catch {
      case e: IncorrectResultSizeDataAccessException => None
    }
  }

  private class RetrievedObjectMapper extends RowMapper[RetrievedRepositoryObject] {
    override def mapRow(rs: ResultSet, rowNum: Int) = {
      RetrievedRepositoryObject(encodedHash = rs.getString("hash"), url = URI.create(rs.getString("url")), encodedObject = rs.getString("encoded_object"))
    }
  }

}

/**
 * Store data on disk.
 */
object DurableDataSource extends BasicDataSource {
  setUrl("jdbc:h2:data/rpki-objects")
  setDriverClassName("org.h2.Driver")
  setDefaultAutoCommit(true)
}

/**
 * For unit testing
 */
object InMemoryDataSource extends BasicDataSource {
  setUrl("jdbc:h2:mem:rpki-objects")
  setDriverClassName("org.h2.Driver")
  setDefaultAutoCommit(true)
}