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
package net.ripe.rpki.validator.fetchers

import java.io.ByteArrayInputStream
import java.net.URI

import net.ripe.ipresource.IpResourceSet
import net.ripe.rpki.validator.config.Http
import net.ripe.rpki.validator.models.validation.{CertificateObject, BrokenObject, RepositoryObject}
import net.ripe.rpki.validator.store.{DataSources, HttpFetcherStore}
import net.ripe.rpki.validator.support.ValidatorTestCase
import org.apache.http.HttpEntity
import org.apache.http.client.methods.{CloseableHttpResponse, HttpGet}
import org.apache.http.impl.client.CloseableHttpClient
import org.mockito.Matchers._
import org.mockito.Mockito.when
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.scalatest.BeforeAndAfter
import org.scalatest.mock.MockitoSugar

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class HttpFetcherTest extends ValidatorTestCase with BeforeAndAfter with MockitoSugar {

  val store = new HttpFetcherStore(DataSources.InMemoryDataSource)

  type FetcherReturnType = Either[BrokenObject, RepositoryObject[_]]

  before {
    store.clear()
  }

  private def readFile(path: String) : String = {
    val is = Thread.currentThread().getContextClassLoader.getResourceAsStream(path)
    scala.io.Source.fromInputStream(is).mkString
  }


  def createMockedFetcher(urls: Map[String, String]) = {
    new HttpFetcher(FetcherConfig(), store) with Http {
      override def http = {
        val httpMock = mock[CloseableHttpClient]
        when(httpMock.execute(any[HttpGet])).thenAnswer(new Answer[CloseableHttpResponse]() {
          override def answer(invocation: InvocationOnMock) = {
            val argument = invocation.getArguments()(0).asInstanceOf[HttpGet]
            val xml = urls(argument.getURI.toString)
            val response = mock[CloseableHttpResponse]
            val entity = mock[HttpEntity]
            when(entity.getContent).thenReturn(new ByteArrayInputStream(xml.getBytes))
            when(response.getEntity).thenReturn(entity)
            response
          }
        })
        httpMock
      }
    }
  }

  def fetchRepo(fetcher: HttpFetcher, rootUrl: String): (List[FetcherReturnType], Seq[String]) = {
    var objects = List[FetcherReturnType]()
    val errors: Seq[String] = fetcher.fetchRepo(new URI(rootUrl)) {
      f => objects = f :: objects
    }
    (objects, errors)
  }

  test("Should download repository when we only have snapshot and no local state") {
    val fetcher = createMockedFetcher(Map(
      "http://repo.net/repo/notification.xml" -> readFile("mock-http-responses/notification1.xml"),
      "http://repo.net/repo/snapshot.xml" -> readFile("mock-http-responses/snapshot1.xml")
    ))

    val (objects, errors) = fetchRepo(fetcher, "http://repo.net/repo/notification.xml")

    errors should have size 0
    objects should have size 1

    val c: CertificateObject = objects.head.right.get.asInstanceOf[CertificateObject]
    c.url should be("rsync://bandito.ripe.net/repo/671570f06499fbd2d6ab76c4f22566fe49d5de60.cer")
    c.decoded.getResources should be(IpResourceSet.parse("192.168.0.0/16"))
  }


  test("Should download repository 1") {
    val fetcher = createMockedFetcher(Map(
      "http://repo.net/repo/notification.xml" -> readFile("mock-http-responses/notification1.xml"),
      "http://repo.net/repo/snapshot.xml" -> readFile("mock-http-responses/snapshot1.xml")
    ))

    val (objects, errors) = fetchRepo(fetcher, "http://repo.net/repo/notification.xml")

    errors should have size 0
    objects should have size 1

    val c: CertificateObject = objects.head.right.get.asInstanceOf[CertificateObject]
    c.url should be("rsync://bandito.ripe.net/repo/671570f06499fbd2d6ab76c4f22566fe49d5de60.cer")
    c.decoded.getResources should be(IpResourceSet.parse("192.168.0.0/16"))
  }

}
