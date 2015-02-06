package net.ripe.rpki.validator.store

import java.net.URI
import javax.sql.DataSource

import org.joda.time.{DateTime, Instant}

trait RepoServiceStorage {
  def getLastFetchTime(uri: URI): Instant
  def updateLastFetchTime(uri: URI, instant: Instant)
}

class RepoServiceStore(dataSource: DataSource) extends RepoServiceStorage {
  val times = scala.collection.mutable.Map[URI,Instant]()


  def getLastFetchTime(uri: URI): Instant = {

    def parentUri(u: URI): Boolean = {
      val uString: String = u.toString
      val uriString = uri.toString

      (uString == uriString) || ( uString.endsWith("/") && uriString.startsWith(uString) ) || uriString.startsWith(uString + "/")
    }

    val instants: Iterable[Instant] = times.filterKeys(parentUri).values
    if (instants.isEmpty) new Instant().withMillis(0)
    else instants.maxBy(_.getMillis)
  }


  def updateLastFetchTime(uri: URI, instant: Instant) = times.put(uri, instant)
}
