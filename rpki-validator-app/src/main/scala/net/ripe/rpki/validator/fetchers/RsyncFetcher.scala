/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * - Neither the name of the RIPE NCC nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
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
package fetchers

import java.io.{PrintWriter, File}
import java.net.URI
import java.nio.file.Files

import net.ripe.rpki.commons.crypto.cms.manifest.{ManifestCms, ManifestCmsParser}
import net.ripe.rpki.commons.crypto.crl.X509Crl
import net.ripe.rpki.commons.crypto.x509cert.{X509CertificateUtil, X509ResourceCertificate, X509ResourceCertificateParser}
import net.ripe.rpki.commons.rsync.Rsync
import net.ripe.rpki.validator.models.validation.{Crl, Certificate, ManifestObject, RepositoryObject}
import org.apache.log4j.Logger
import org.bouncycastle.jce.provider.X509CRLParser

import scala.collection.JavaConversions._
import scala.reflect.io.Path

class RsyncFetcher {

  private val logger: Logger = Logger.getLogger(classOf[RsyncFetcher])

  private val OPTIONS = Seq("--update", "--times", "--copy-links", "--recursive")

  private def walkTree[T](d: File)(f: File => Option[T]): Seq[T] = {
    if (d.isDirectory) {
      val (dirs, files) = d.listFiles.partition(_.isDirectory)
      files.map(f).collect { case Some(x) => x} ++ dirs.toSeq.map(walkTree(_)(f)).flatten
    } else Seq[T]()
  }

  def getCertificateUrl(certificate: X509ResourceCertificate): String = ""

  def getManifestUrl(cms: ManifestCms) = ""

  def getCrlUrl(crl: X509Crl) = ""

  private[this] def withTempDir[T](f: File => T) = {
    def deleteTree(f: File) {
      if (f.isDirectory)
        f.listFiles.foreach(deleteTree)
      f.delete()
    }

    val destDir = {
      val path = Files.createTempDirectory("rsync-tmp-")
      val dir = path.toFile
      if (!dir.exists) dir.mkdir
      dir
    }
    val result = try {
      f(destDir)
    } finally {
      deleteTree(destDir)
    }
    result
  }

  def fetchRepo(uri: URI) = withTempDir {
    tmpDir =>
      logger.info(s"Downloading the repository $uri to ${tmpDir.getAbsolutePath}")
      val r = new Rsync(uri.toString, tmpDir.getAbsolutePath)
      r.addOptions(OPTIONS)
      r.execute match {
        case 0 => Right(readObjects(tmpDir))
        case code => Left(r.getErrorLines.mkString("\n"))
      }
  }

  def readObjects(dir: File): Seq[RepositoryObject] = {
    val pw = new PrintWriter(new File("repo.log" ))
    walkTree(dir) {
      f =>
        if (f.getName.endsWith(".cer")) {
          val parser = new X509ResourceCertificateParser
          parser.parse(f.getAbsolutePath, readFile(f))
          val certificate = parser.getCertificate
          val ski = certificate.getSubjectKeyIdentifier
          val hash = ski.map { b => String.format("%02X", new java.lang.Integer(b & 0xff))}.mkString
          pw.println(s"$f; $hash")
          Some(Certificate(getCertificateUrl(certificate), ski, certificate))
        } else if (f.getName.endsWith(".mft")) {
          val parser = new ManifestCmsParser
          parser.parse(f.getAbsolutePath, readFile(f))
          val manifest = parser.getManifestCms
          // TODO create getAki method
          val aki = manifest.getCertificate.getSubjectKeyIdentifier
          val hash = aki.map { b => String.format("%02X", new java.lang.Integer(b & 0xff))}.mkString
          pw.println(s"$f; $hash")
          Some(ManifestObject(getManifestUrl(manifest), aki, manifest))
        } else if (f.getName.endsWith(".crl")) {
          val crl = new X509Crl(readFile(f))
          val aki = crl.getAuthorityKeyIdentifier
          Some(Crl(getCrlUrl(crl), aki, crl))
        } else
          None

    }
  }


  private def readFile(f: File) = Files.readAllBytes(f.toPath)

}