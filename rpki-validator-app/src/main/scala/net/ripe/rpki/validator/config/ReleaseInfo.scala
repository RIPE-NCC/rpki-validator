package net.ripe.rpki.validator.config

import java.io.File
import scala.collection.JavaConversions.propertiesAsScalaMap
import grizzled.slf4j.Logger

object ReleaseInfo {
  val logger = Logger[this.type]
  val releasePropertiesFilePath = "/version.properties"
  val data = loadFile()

  def loadFile() : Option[Map[String,String]] = {
    try {
      val props = new java.util.Properties
      props.load(new java.io.FileInputStream(new File(getClass().getResource(releasePropertiesFilePath).toURI)))
      Some(propertiesAsScalaMap(props).toMap.withDefaultValue(""))
    } catch {
      case e: Exception =>
        logger.error("Error while loading release property file " + releasePropertiesFilePath, e)
        None
    }
  }

  def apply(key: String) = data.map(_(key)).getOrElse("")

  val version: String = ReleaseInfo("version")
}
