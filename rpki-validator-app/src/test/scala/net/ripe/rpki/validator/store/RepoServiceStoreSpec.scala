package net.ripe.rpki.validator.store

import java.net.URI

import org.joda.time.Instant
import org.scalacheck.{Arbitrary, Gen}
import org.scalatest.PropSpec
import org.scalatest.matchers.ShouldMatchers
import org.scalatest.prop.GeneratorDrivenPropertyChecks

class RepoServiceStoreSpec extends PropSpec with GeneratorDrivenPropertyChecks with ShouldMatchers {

  val instantGenerator: Gen[Instant] = for {
    long <- Arbitrary.arbitrary[Long]
  } yield new Instant(long)

  val uriGenerator: Gen[URI] = for {
    scheme <- Gen.oneOf("http", "rsync")
    host <- Gen.alphaStr suchThat (_.length > 0)
    path <- Gen.alphaStr suchThat (_.length > 0)
  } yield new URI(scheme, host, s"/$path", null)

  implicit val arbInstant: Arbitrary[Instant] = Arbitrary(instantGenerator)
  implicit val arbUri: Arbitrary[URI] = Arbitrary(uriGenerator)

  property("getLastFetchTime should return time of updateLastFetchTime") {
    forAll { (i: Instant, u: URI) =>
      RepoServiceStore.updateLastFetchTime(u, i)
      RepoServiceStore.getLastFetchTime(u) should be(i);
    }
  }

}
