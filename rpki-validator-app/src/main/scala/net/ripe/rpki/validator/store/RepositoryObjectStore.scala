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

trait DbMigrations {

  def getDataSource: DataSource
  def getSqlMigrationsDir: String
  def getCodeMigrationsPackage: String

  // Is it bad style to do initialisation stuff implicitly like this, when an instance is constructed? Or should we have an init method?
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

  def put(retrievedObject: RetrievedRepositoryObject) = {
    template.update("insert into retrieved_objects (hash, url, encoded_object) values(?,?,?)", Array[Object](retrievedObject.encodedHash , retrievedObject.url.toString, retrievedObject.encodedObject))
  }

  def retrieveByUrl(url: URI) = {
    template.queryForObject("select * from retrieved_objects where url = ?", Array[Object](url.toString), new RetrievedObjectMapper()).asInstanceOf[RetrievedRepositoryObject]
  }

  private class RetrievedObjectMapper extends RowMapper {

    def mapRow(rs: ResultSet, rowNum: Int): Object = {
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
}

/**
 * For unit testing
 */
object InMemoryDataSource extends BasicDataSource {
  setUrl("jdbc:h2:mem:rpki-objects")
  setDriverClassName("org.h2.Driver")
}