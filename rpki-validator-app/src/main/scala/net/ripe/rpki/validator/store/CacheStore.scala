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
import org.springframework.jdbc.core.{RowMapper, JdbcTemplate}
import scala.collection.JavaConversions._

trait Storage {

  def storeCertificate(certificate: CertificateObject)

  def storeManifest(manifest: ManifestObject)

  def storeCrl(crl: CrlObject)

  def storeRoa(Roa: RoaObject)

  def getCertificates(aki: Array[Byte]): Seq[CertificateObject]

}

class CacheStore(dataSource: DataSource) extends Storage with Hashing {

  val template: JdbcTemplate = new JdbcTemplate(dataSource)

  override def storeCertificate(certificate: CertificateObject): Unit = {
    template.update(
      "insert into certificates(aki, ski, hash, url, encoded) values (?, ?, ?, ?, ?)",
      stringify(certificate.aki),
      stringify(certificate.ski),
      stringify(certificate.hash),
      certificate.url,
      certificate.encoded)
  }

  override def storeRoa(roa: RoaObject): Unit = {
    template.update(
      "insert into roas(aki, hash, url, encoded) values (?, ?, ?, ?)",
      stringify(roa.aki),
      stringify(roa.hash),
      roa.url,
      roa.encoded)
  }

  override def storeManifest(manifest: ManifestObject): Unit = {
    template.update(
      "insert into manifests(aki, hash, url, encoded) values (?, ?, ?, ?)",
      stringify(manifest.aki),
      stringify(manifest.hash),
      manifest.url,
      manifest.encoded)
  }

  override def storeCrl(crl: CrlObject): Unit = {
    template.update(
      "insert into crls(aki, hash, url, encoded) values (?, ?, ?, ?)",
      stringify(crl.aki),
      stringify(crl.hash),
      crl.url,
      crl.encoded)
  }

  override def getCertificates(aki: Array[Byte]): Seq[CertificateObject] = {
    template.query("SELECT url, ski, encoded FROM certificates WHERE aki = ?", new RowMapper[CertificateObject] {
      override def mapRow(rs: ResultSet, i: Int) =
        CertificateObject(
          url = rs.getString(1),
          aki = aki,
          ski = stringToBytes(rs.getString(2)),
          encoded = rs.getBytes(3))
    }, stringify(aki)).toSeq
  }

  def clear() = {
    for (t <- Seq("certificates", "manifests", "crls", "roas"))
      template.update(s"TRUNCATE TABLE $t")
  }

}
