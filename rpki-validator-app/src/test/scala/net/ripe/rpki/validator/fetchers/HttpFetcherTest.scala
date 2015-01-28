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

  test("Should download repository") {
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
