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
package net.ripe.rpki.validator.config

import java.io.{BufferedInputStream, File, FileInputStream}
import java.security.KeyStore
import java.security.cert.{CertificateFactory, X509Certificate}
import javax.net.ssl.{TrustManagerFactory, X509TrustManager}

import grizzled.slf4j.Logging
import org.apache.http.client.config.RequestConfig
import org.apache.http.conn.ssl.SSLContexts
import org.apache.http.impl.client.{CloseableHttpClient, HttpClientBuilder}

import scala.util.{Failure, Success, Try}

trait Http { this: Logging =>

  def trustedCertsLocation: File

  private val customKeyStore = KeyStore.getInstance("jceks")
  customKeyStore.load(null)

  private val systemTrustedCertificates = {
    val tmf = TrustManagerFactory.getInstance("PKIX")
    tmf.init(null.asInstanceOf[KeyStore])
    tmf.getTrustManagers.filter(_.isInstanceOf[X509TrustManager]).flatMap(_.asInstanceOf[X509TrustManager].getAcceptedIssuers)
  }

  systemTrustedCertificates.foreach(cert => putCertificateInKeyStore(cert))
  loadCertificatesFromDir(trustedCertsLocation) foreach {
    case Success(cert) => putCertificateInKeyStore(cert)
    case Failure(e) => logger.error(e)
  }

  private def loadCertificatesFromDir(dir: File): Array[Try[X509Certificate]] = {
    val cf = CertificateFactory.getInstance("X.509")

    def loadCertificateFromFile(f: File): Try[X509Certificate] = {
      Try {
        cf.generateCertificate(new BufferedInputStream(new FileInputStream(f))).asInstanceOf[X509Certificate]
      } recoverWith {
        case e: Exception =>
          Failure(new RuntimeException(s"Error loading certificate from file $f: ${e.getMessage}", e))
      }
    }
    try {
      dir.listFiles().filter(_.isFile).map(f => loadCertificateFromFile(f))
    } catch {
      case e: Exception =>
        Array(Failure(new RuntimeException(s"Error reading trusted certificates from $dir: ${e.getMessage}", e)))
    }
  }

  private def putCertificateInKeyStore(cert: X509Certificate): Unit = {
    customKeyStore.setCertificateEntry(cert.getSubjectDN.getName, cert)
  }

  private val httpRequestConfig = RequestConfig.custom()
    .setConnectTimeout(2 * 60 * 1000)
    .setSocketTimeout(2 * 60 * 1000)
    .build()

  private val customSslContext = SSLContexts.custom()
    .useTLS()
    .loadTrustMaterial(customKeyStore)
    .build()

  private val httpClient: CloseableHttpClient = HttpClientBuilder.create()
    .useSystemProperties()
    .setDefaultRequestConfig(httpRequestConfig)
    .setSslcontext(customSslContext)
    .build()

  def http = httpClient
}
