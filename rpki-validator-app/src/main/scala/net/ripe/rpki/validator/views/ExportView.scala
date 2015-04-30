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
package net.ripe.rpki.validator.views
import scala.xml.Text

class ExportView extends View with ViewHelpers {

  def tab = Tabs.ExportTab
  def title = Text("Export and API")
  def body = {
    <h2>Export</h2>
      <p>
        Here you are able to export the complete ROA data set for use in an existing BGP decision making workflow. The
        output will be in CSV, JSON or RPSL format and consist of all validated ROAs, minus your ignore filter entries,
        plus your whitelist additions. The output in RPSL format is in <strong>beta</strong>, please refer to the
        README for details.
      </p>
      <div class="alert-actions">
        <a href="export.csv" class="btn">Get CSV</a>
        <a href="export.json" class="btn">Get JSON</a>
        <a href="export.rpsl" class="btn">Get RPSL</a>
        <span class="help-inline">
          These are stable links, so you can use a tool such as wget from cron to periodically get this export.
        </span>
        </div><br /><br />
      <h2>API</h2>
      <p>You can ask this RPKI Validator for validity information about a BGP announcement. You will get a response in JSON format containing the following data:</p>
      <ul>
        <li>The RPKI validity state, as described in <a href="http://tools.ietf.org/html/rfc6811">RFC 6811</a></li>
        <li>The validated ROA prefixes that caused the state</li>
        <li>In case of an 'Invalid' state, the reason:</li>
        <ul>
          <li>The prefix is originated from an unauthorised AS</li>
          <li>The prefix is more specific than allowed in the Maximum Length of the ROA</li>
        </ul>
      </ul>
      <h3>Examples</h3>

      <div class="well monospace">
        GET /api/v1/validity/:ASN/:prefix
      </div>
      <table class="monospace">
        <tr>
          <td>Valid</td><td>{apiLink("AS12654", "93.175.146.0/24")}</td>
        </tr>
        <tr>
          <td>Invalid (AS)</td><td>{apiLink("AS12654", "93.175.147.0/24")}</td>
        </tr>
        <tr>
          <td>Invalid (length)</td><td>{apiLink("AS196615", "93.175.147.0/25")}</td>
        </tr>
        <tr>
          <td>Not Found</td><td>{apiLink("AS12654", "2001:7fb:ff03::/48")}</td>
        </tr>
      </table>
      <p>You can find additional documentation <a href="https://www.ripe.net/data-tools/developer-documentation/rpki-validator-api">here</a>.</p>
  }

  def apiLink(asn: String, prefix: String) = {
    val link = s"/api/v1/validity/$asn/$prefix"
    <a href={link}>{link}</a>
  }

}
