package net.ripe.rpki.validator.controllers

import org.scalatra.ScalatraKernel
import net.ripe.rpki.validator.lib.{SoftwareUpdatePreferences, SoftwareUpdateChecker}


trait PreferencesController extends ScalatraKernel with SoftwareUpdateChecker {

  def updateUserPreferences(userPreferences: SoftwareUpdatePreferences)
  
  get("/set-update-check/:state") {
    params("state") match {
      case "true" => updateUserPreferences(SoftwareUpdatePreferences(true))
      case "false" => updateUserPreferences(SoftwareUpdatePreferences(false))
    }
    redirect("/")
  }
}
