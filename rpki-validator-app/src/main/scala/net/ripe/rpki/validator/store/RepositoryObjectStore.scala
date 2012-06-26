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

  private def getOptionalResult(selectString: java.lang.String, selectArgs: Array[java.lang.Object]): Option[net.ripe.rpki.validator.models.RetrievedRepositoryObject] = {
    try {
      Some(template.queryForObject(selectString, selectArgs, new RetrievedObjectMapper()))
    } catch {
      case e: IncorrectResultSizeDataAccessException => None
    }
  }

  private class RetrievedObjectMapper extends RowMapper[RetrievedRepositoryObject] {
    def mapRow(rs: ResultSet, rowNum: Int) = {
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