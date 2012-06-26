package net.ripe.rpki.validator
package store

import models._
import org.scalatest.FunSuite
import org.scalatest.matchers.ShouldMatchers
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest
import net.ripe.commons.certification.cms.manifest.ManifestCms
import java.net.URI
import org.scalatest.BeforeAndAfter

@org.junit.runner.RunWith(classOf[org.scalatest.junit.JUnitRunner])
class RepositoryObjectStoreTest extends FunSuite with BeforeAndAfter with ShouldMatchers {

  val EXAMPLE_MANIFEST = ManifestCmsTest.getRootManifestCms
  val EXAMPLE_MANIFEST_URI = URI.create("rsync://some.host/example.mft")
  val EXAMPLE_MANIFEST_OBJECT = RetrievedRepositoryObject(url = EXAMPLE_MANIFEST_URI, repositoryObject = EXAMPLE_MANIFEST)

  val store = new RepositoryObjectStore(InMemoryDataSource)

  before {
    store.put(EXAMPLE_MANIFEST_OBJECT)
  }

  test("Should retrieve Repository Object by url") {
    store.retrieveByUrl(EXAMPLE_MANIFEST_URI) should equal(EXAMPLE_MANIFEST_OBJECT)
  }

}