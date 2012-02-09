package net.ripe.rpki.validator.controllers

import org.scalatra.ScalatraKernel
import net.ripe.rpki.validator.lib.{UserPreferences, SoftwareUpdateChecker}


trait UserPreferencesController extends ScalatraKernel with SoftwareUpdateChecker {

  def updateUserPreferences(userPreferences: UserPreferences)
  
  get("/set-update-alert/:state") {
    params("state") match {
      case "true"   => updateUserPreferences(UserPreferences(updateAlertActive = true))
      case "false"  => updateUserPreferences(UserPreferences(updateAlertActive = false))
    }
    redirect("/")
  }
}
