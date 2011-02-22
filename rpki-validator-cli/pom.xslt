<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:mvn="http://maven.apache.org/POM/4.0.0">

    <xsl:output method="text" media-type="text/plain" />

    <xsl:template match="/">
        <xsl:value-of select="mvn:project/mvn:parent/mvn:version" />
    </xsl:template>

</xsl:stylesheet>