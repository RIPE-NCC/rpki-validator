/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.rpki.validator
package views

import scala.xml.Text

class HomeView extends View with ViewHelpers {

  def tab = views.Tabs.HomeTab
  def title = Text("Quick overview of BGP Origin validation")
  def body = {
    
    
    <br/>

        <div class="row">
            <div class="span2 offset2 stepOverhead"><img src="images/arrowTop.png" width="101" height="35" alt="ArrowTop" /></div>
            <div class="span2 offset1 stepOverhead">&nbsp;</div>
            <div class="span2 offset1 stepOverhead"><img src="images/arrowTop.png" width="101" height="35" alt="ArrowTop" /></div>
            <div class="span2 offset1 stepOverhead">&nbsp;</div>
        </div>
        
        
        <div class="row">
            <div class="span3 stepTitle selected"><a href="#trustAnchors"><h3>Trust Anchors</h3></a></div>
            <div class="span3 stepTitle"><a href="#roas"><h3>ROAs</h3></a></div>
            <div class="span3 stepTitle"><a href="#ignoreFilters"><h3>Ignore Filters</h3></a></div>
            <div class="span3 stepTitle"><a href="#whitelist"><h3>Whitelist</h3></a></div>
            <div class="span3 stepTitle"><a href="#router"><h3>Router</h3></a></div>
        </div>
        <div class="row">
            <div class="span2 offset2 stepOverhead">&nbsp;</div>
            <div class="span2 offset1 stepOverhead"><img src="images/arrowBottom.png" width="101" height="35" alt="ArrowTop" /></div>
            <div class="span2 offset1 stepOverhead">&nbsp;</div>
            <div class="span2 offset1 stepOverhead"><img src="images/arrowBottom.png" width="101" height="35" alt="ArrowTop" /></div>
        </div>
        
        <br/>
        <div class="row">
            <div id="trustAnchorsPointer" class="span3 stepArrow selected">&nbsp;</div>
            <div id="roasPointer" class="span3 stepArrow">&nbsp;</div>
            <div id="ignoreFiltersPointer" class="span3 stepArrow">&nbsp;</div>
            <div id="whitelistPointer" class="span3 stepArrow">&nbsp;</div>
            <div id="routerPointer" class="span3 stepArrow">&nbsp;</div>
        </div>
        <div class="row">
            <div class="span16">
                    <div id="trustAnchors" class="stepDescription selected">
                        <p>
                          Trust Anchors are the entry points used for validation in any
                          Public Key Infrastructure (PKI) system. This validator is intended for the validation
                          of Resource PKI (RPKI) systems. It is pre-configured with Trust Anchors for four
                          RIRs who are running such systems now.
                        </p>
                        <br />
                        <p>
                          If you would like to add or change which Trust Anchors are used by this
                          validator, please see the README.txt file for details.
                        </p>
                    </div>
                    <div id="roas" class="stepDescription">
                        <p>
                          Route Origin Attestations (ROAs) are used in the RPKI to authorise specific ASNs
                          to originate prefixes. Only the legitimate holder of the prefix can create a valid ROA.
                        </p>
                        <p>
                          It should be noted that ROAs are intended to be positive attestations, but the presence of
                          a ROA for an ASN and prefix combination implies that announcements for this prefix from
                          <strong>other</strong> origin ASNs, or for <strong>more specific</strong> prefixes should be considered
                          invalid.
                        </p>
                        <p>
                          More than one ROA may exist for the same prefix, and as long as one of
                          them matches the announcement it is considered valid. The announcement validation rules
                          are defined in an IETF standard, and will be explained in more detail in the 'Router' section.
                        </p>
                    </div>
                    <div id="ignoreFilters" class="stepDescription">
                        <p>
                          Because ROAs may invalidate certain announcements, and you as an operator may disagree, this validation
                          tools allows you to <strong>ignore</strong> all ROAs that would otherwise affect certain prefixes.
                        </p>
                        <p>
                          If you use this option it will be as though no ROAs exist for this prefix.
                        </p>
                    </div>
                    <div id="whitelist" class="stepDescription">
                        <p>
                          Continuing this thought you may actually want to add your own whitelist entries for announcement
                          that don't have a corresponding ROA, but in your mind should have.
                        </p>
                        <p>
                          If you use this option it will be as though a ROAs exist for this announcement.
                        </p>
                    </div>
                    <div id="router" class="stepDescription">
                        <p>
                            <h3>RPKI RTR</h3>
      <p>
          You can configure your router to connect to this validator so that it can receive a full set
          of <strong>Route Origin Attestations</strong>
          based on all the ROAs that were validated, minus your ignore list entries, plus your own whitelist entries.
      </p>
      <p>
          The protocol for this is being standardised in the IETF and a number of vendors are currently implementing
          support for this in their router Operating Systems.
      </p>
      <br/>
      <h3>Announcement Validation in the Router</h3>
      <p>
        Once your router receives the <strong>Route Origin Attestations</strong>
        it can now use this information to determine the validity outcome of the origin
        AS in BGP announcements. To do this your router will match an announcement to
        each attestation in this way:
      </p>
      <br />
      <table>
        <tr>
          <td>Annoucement has</td>
          <td>an origin AS matching the attestation</td>
          <td>an origin AS that differs from the attestation</td>
        </tr>
        <tr>
          <td>a prefix matching the attestation</td>
          <td>VALID</td>
          <td>INVALID</td>
        </tr>
        <tr>
          <td>a prefix that is more specific than the attestation</td>
          <td>INVALID</td>
          <td>INVALID</td>
        </tr>
      </table>
      In all other cases no conclusive decision can be made and the resulting status is 'UNKNOWN'
      <br />
      <br />
      <p>
          The final judgement whether an announcement should be considered valid, invalid or unknown
          depends on <strong>all</strong> relevant attestations using the following reasoning:
      </p>

      <p>
        <table>
          <tr><td>at least 1 VALID</td><td>VALID</td></tr>
          <tr><td>no VALIDS, at least 1 INVALID</td><td>INVALID</td></tr>
          <tr><td>none of the above</td><td>UNKNOWN</td></tr>
        </table>
        <span rel="popover" data-content={
              <div>
                  <p>Consider the following Attestations</p>
                  <table>
                      <tr><td>&nbsp;</td><td>ASN</td><td>Prefix</td><td>Max Length</td></tr>
                      <tr><td>A</td><td>65001</td><td>10.0.0.0/16</td><td>20</td></tr>
                      <tr><td>B</td><td>65002</td><td>10.0.1.0/24</td><td>24</td></tr>
                  </table>
                  <p>Then the following Announcements would get validation statuses:</p>
                  <table>
                      <tr><td>ASN</td><td>Prefix</td><td>Status</td><td>Reason</td></tr>
                      <tr><td>65001</td><td>10.0.0.0/16</td><td>VALID</td><td>matches A</td></tr>
                      <tr><td>65001</td><td>10.0.0.0/24</td><td>INVALID</td><td>no valid matches, more specific than A</td></tr>
                      <tr><td>65002</td><td>10.0.1.0/24</td><td>VALID</td><td>matches B (A invalidates, B wins)</td></tr>
                      <tr><td>65004</td><td>10.0.2.0/20</td><td>INVALID</td><td>no valid matches, different AS from A</td></tr>
                      <tr><td>65004</td><td>192.168.0.0/24</td><td>UNKNOWN</td><td>no matches</td></tr>
                  </table>
                  </div>
            } data-original-title="Example"><a href="#">See an example....</a></span>
      </p>
      <br />
      <p>
          This information is now available to your router and can be used to make automatically change the preference
          of route announcements. The way this is configured differs between vendors of course. The advice in the IETF
          standards is to prefer valid, over unknown, over invalid. But it's up to you as an operator to decide if and
          how you want to use this information.
      </p>
      <br />
      <h3>BGP Preview</h3>
      <p>
          The decision process described above takes place in your <strong>router</strong>. Only the router gets to see
          the actual BGP announcements, so only the router can make this assessment.
      </p>
      <p>
          However, to help you analyse what your router will most likely see we have created the <a href="/bgp-preview">BGP Preview</a>
          page. On this page we mimic the announcement validation process described above using a dump of announcements that are widely (>5 peers)
          <a href="http://www.ris.ripe.net/dumps/">seen</a> by the RIPE NCC RIS Route Collectors.
      </p>
      <p>
          This page is provided for two main reasons:
          <ul>
            <li>to help you set up your own ignore filters and whitelist entries</li>
            <li>to help you analyse BGP announcement validatity outside of your router, this is useful if you prefer a more manual approach and don't want your router to take automated decisions using this..</li>
          </ul>
      </p>

                        </p>
                    </div>
            </div>
            <div class="span1"></div>
        </div>
        <br/><br/><br/><br/>


          <script><!--
$(document).ready(function() {
  $('[rel=popover]').popover({
    "live": true,
    "html": true,
    "placement": "below",
    "offset": 10
  }).live('click', function (e) {
    e.preventDefault();
  });
$(".stepTitle a").click(function(e){
                    navigate($(this), e);
                });
                
                function navigate(el, event){
                    event.preventDefault();
                    $(".stepTitle").removeClass("selected");
                    el.parent().addClass("selected");
                    $(".stepDescription.selected").removeClass("selected");
                    $(el.attr("href")).addClass("selected");                
                    $(".stepArrow").removeClass("selected");
                    $(el.attr("href")+"Pointer").addClass("selected");
                };
});
// --></script>
        
  }

}