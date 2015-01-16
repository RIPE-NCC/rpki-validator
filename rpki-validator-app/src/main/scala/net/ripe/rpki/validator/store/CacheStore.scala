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

import java.sql.ResultSet
import javax.sql.DataSource

import net.ripe.rpki.validator.models.validation._
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate
import org.springframework.jdbc.core.RowMapper
import scala.collection.JavaConversions._

trait Storage {

  def storeCertificate(certificate: CertificateObject)

  def storeManifest(manifest: ManifestObject)

  def storeCrl(crl: CrlObject)

  def storeRoa(Roa: RoaObject)

  def storeBroken(brokenObject: BrokenObject): Unit = ???

  def getCertificates(aki: Array[Byte]): Seq[CertificateObject]

  def getCrls(aki: Array[Byte]): Seq[CrlObject]

  def getRoas(aki: Array[Byte]): Seq[RoaObject]

  def getManifests(aki: Array[Byte]): Seq[ManifestObject]
}

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  val template: NamedParameterJdbcTemplate = new NamedParameterJdbcTemplate(dataSource)

  override def storeCertificate(certificate: CertificateObject) =
    template.update(
      "INSERT INTO certificates(aki, ski, hash, url, encoded) VALUES (:aki, :ski, :hash, :url, :encoded)",
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
      """INSERT INTO repo_objects(aki, hash, url, encoded, type)
         SELECT :aki, :hash, :url, :encoded, :type
         WHERE NOT EXISTS (
           SELECT * FROM repo_objects ro
           WHERE ro.hash = :hash AND ro.url = :url
         )
      """,
      Map("aki" -> stringify(obj.aki),
        "hash" -> stringify(obj.hash),
        "url" -> obj.url,
        "encoded" -> obj.encoded,
        "type" -> objType))
  }

  override def getCertificates(aki: Array[Byte]): Seq[CertificateObject] =
    template.query("SELECT url, ski, encoded FROM certificates WHERE aki = :aki",
      Map("aki" -> stringify(aki)),
      new RowMapper[CertificateObject] {
        override def mapRow(rs: ResultSet, i: Int) = CertificateObject.parse(rs.getString(1), rs.getBytes(3))
      }).toSeq

  def getCrls(aki: Array[Byte]) = getRepoObject[CrlObject](aki, "crl") {
    (url, encoded) => CrlObject.parse(url, encoded)
  }

  def getManifests(aki: Array[Byte]) = getRepoObject[ManifestObject](aki, "manifest") {
    (url, encoded) => ManifestObject.parse(url, encoded)
  }

  def getRoas(aki: Array[Byte]) = getRepoObject[RoaObject](aki, "roa") { RoaObject.parse }

  private def getRepoObject[T](aki: Array[Byte], objType: String)(mapper: (String, Array[Byte]) => T) =
    template.query("SELECT url, encoded FROM repo_objects WHERE aki = :aki AND type = :type",
      Map("aki" -> stringify(aki), "type" -> objType),
      new RowMapper[T] {
        override def mapRow(rs: ResultSet, i: Int) = mapper(rs.getString(1), rs.getBytes(2))
      }).toSeq

  def clear() = {
    for (t <- Seq("certificates", "repo_objects"))
      template.update(s"TRUNCATE TABLE $t", Map[String, Object]())
  }

}
