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

import java.io.{BufferedInputStream, File, FileInputStream, InputStream}
import java.security.KeyStore
import java.security.cert.{CertificateFactory, X509Certificate}
import javax.net.ssl.{SSLException, TrustManagerFactory, X509TrustManager}

import grizzled.slf4j.Logging
import net.ripe.rpki.validator.lib.DateAndTime._
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpGet
import org.apache.http.conn.ssl.{SSLConnectionSocketFactory, SSLContexts, TrustStrategy}
import org.apache.http.impl.client.HttpClientBuilder
import org.joda.time.DateTime

import scala.util.control.NonFatal
import scala.util.{Failure, Success, Try}

trait Http { this: Logging =>

  def trustedCertsLocation: File

  private val customKeyStore = KeyStore.getInstance("jceks")
  customKeyStore.load(null)

  private val systemTrustedCertificates = {
    val tmf = TrustManagerFactory.getInstance("PKIX")
    tmf.init(null.asInstanceOf[KeyStore])
    tmf.getTrustManagers.withFilter(_.isInstanceOf[X509TrustManager]).flatMap(_.asInstanceOf[X509TrustManager].getAcceptedIssuers)
  }

  systemTrustedCertificates.foreach(putCertificateInKeyStore)
  loadCertificatesFromDir(trustedCertsLocation).foreach {
    case Success(cert) => putCertificateInKeyStore(cert)
    case Failure(e) => logger.error(e)
  }

  private def loadCertificatesFromDir(dir: File): Array[Try[X509Certificate]] = {
    lazy val cf = CertificateFactory.getInstance("X.509")
    def loadCertificateFromFile(f: File): Try[X509Certificate] = {
      Try {
        cf.generateCertificate(new BufferedInputStream(new FileInputStream(f))).asInstanceOf[X509Certificate]
      } recoverWith {
        case e: Exception =>
          Failure(new RuntimeException(s"Error loading certificate from file $f: ${e.getMessage}", e))
      }
    }

    if (!dir.isDirectory) {
      Array()
    } else {
      try {
        dir.listFiles().withFilter(f => f.isFile && !f.getName.equals(".keep")).map(f => loadCertificateFromFile(f))
      } catch {
        case e: Exception =>
          Array(Failure(new RuntimeException(s"Error reading trusted certificates from $dir: ${e.getMessage}", e)))
      }
    }
  }

  private def putCertificateInKeyStore(cert: X509Certificate): Unit = {
    customKeyStore.setCertificateEntry(cert.getSubjectDN.getName, cert)
  }

  private val httpRequestConfig = RequestConfig.custom()
    .setConnectTimeout(11 * 1000)
    .setSocketTimeout(29 * 1000)
    .build()

  private val customSslContext = SSLContexts.custom()
    .useTLS()
    .loadTrustMaterial(customKeyStore)
    .build()

  private val httpClient = HttpClientBuilder.create()
    .useSystemProperties()
    .setDefaultRequestConfig(httpRequestConfig)
    .setSslcontext(customSslContext)
    .build()

  private lazy val wrongSslHttp = {
    val acceptingTrustStrategy = new TrustStrategy() {
      override def isTrusted(chain: Array[X509Certificate], authType: String) = true
    }

    val emptyKeyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    emptyKeyStore.load(null.asInstanceOf[InputStream], "".toCharArray)

    val sslConext = SSLContexts.custom()
      .useTLS()
      .loadTrustMaterial(emptyKeyStore, acceptingTrustStrategy)
      .build()

    val socketFactory = new SSLConnectionSocketFactory(sslConext,
      SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)

    HttpClientBuilder.create()
      .setSSLSocketFactory(socketFactory)
      .build()
  }

  def http = httpClient

  private var invalidSslHosts = Set[String]()

  private def fallBackToInsecureSsl[T](get: HttpGet) = {
    val url = get.getURI
    if (url.getScheme == "https") {
      if (invalidSslHosts.contains(url.getHost)) {
        wrongSslHttp.execute(get)
      } else {
        try {
          http.execute(get)
        } catch {
          case e: SSLException =>
            logger.error(s"Could not establish SSL connection while retrieving $url, trying to establish SSL connection without certificate check.", e)
            url.synchronized {
              invalidSslHosts = invalidSslHosts + url.getHost
            }
            wrongSslHttp.execute(get)
          case NonFatal(e) =>
            logger.error("Something bad happened while retrieving " + url)
            throw e
        }
      }
    } else {
      http.execute(get)
    }
  }

  def httpGet(url: String) = fallBackToInsecureSsl(new HttpGet(url))

  def httpGetIfNotModified(url: String, ifModifiedSince: Option[DateTime]) = {
    val get = new HttpGet(url)
    ifModifiedSince.foreach { t =>
      get.setHeader("If-Modified-Since", formatAsRFC2616(t))
    }
    fallBackToInsecureSsl(get)
  }

}
