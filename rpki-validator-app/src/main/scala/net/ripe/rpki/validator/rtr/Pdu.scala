package net.ripe.rpki.validator.rtr


trait PduWriter {
  def toBytes: Array[Byte]
}

case class ErrorPdu(val errorCode: Int) extends PduWriter {

  val protocolVersion: Byte = 0
  val pduType: Byte = 10
  
  val causingPdu: String = ""
  val errorText: String = ""
  
  override def toBytes: Array[Byte] = {
    var causingPduLength = causingPdu.length()
    var errorTextLength = errorText.length()
    var totalLength = 8 + 4 + causingPduLength + 4 + errorTextLength
    
    val bytes: Array[Byte] = new Array[Byte](totalLength)
    bytes(0) = protocolVersion
    
    
    null // TODO convert to array and more...
  }
  
}

object ErrorPdus {
  val NoDataAvailable = 2
}
