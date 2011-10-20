package net.ripe.rpki.validator
package views

import scala.xml._
import lib.Validation._

trait ViewHelpers {
  protected[this] def renderErrors(errors: Seq[ErrorMessage], fieldNameToText: String => String): NodeSeq = if (errors.nonEmpty) {
    <div class="alert-message block-message error">
      <strong>Please fix the following errors and resubmit the form</strong>
      <ul>
        {
          for (error <- errors) yield <li>{ error.fieldName.map(name => fieldNameToText(name) + ": ").getOrElse("") + error.message }</li>
        }
      </ul>
    </div>
  } else {
    NodeSeq.Empty
  }
}
