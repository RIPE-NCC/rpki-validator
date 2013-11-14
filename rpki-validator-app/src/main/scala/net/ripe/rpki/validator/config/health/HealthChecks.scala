package net.ripe.rpki.validator.config.health

import com.codahale.metrics.health.{HealthCheck, HealthCheckRegistry}
import net.ripe.rpki.commons.rsync.Rsync

object HealthChecks {
  val registry = new HealthCheckRegistry
  registry.register("rsync", new RsyncHealthCheck)
}

class RsyncHealthCheck extends HealthCheck {

  override def check(): HealthCheck.Result = try {
    val rsync = new Rsync
    rsync.addOptions("--version")
    val rc = rsync.execute()

    if (rc == 0) {
      return HealthCheck.Result.healthy("can find and execute rsync")
    } else {
      return HealthCheck.Result.unhealthy("problems executing rsync, make sure you have rsync installed on the path")
    }
  } catch {
    case e: Exception => return HealthCheck.Result.unhealthy(e.getMessage)
  }

}
