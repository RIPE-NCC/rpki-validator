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

import scala.xml._

case class Tab(text: NodeSeq, url: String)

object Tabs {
  val HomeTab = Tab(Text("Home"), "/")
  val TrustAnchorsTab = Tab(Text("Trust Anchors"), "/trust-anchors")
  val RoasTab = Tab(Text("ROAs"), "/roas")
  val FiltersTab = Tab(Text("Ignore Filters"), "/filters")
  val WhitelistTab = Tab(Text("Whitelist"), "/whitelist")
  val BgpPreviewTab = Tab(Text("BGP Preview"), "/bgp-preview")
  val ExportTab = Tab(Text("Export and API"), "/export")
  val RtrSessionsTab = Tab(Text("Router Sessions"), "/rtr-sessions")
  val RtrLogTab = Tab(Text("rpki-rtr log"), "/rtr-log")
  val ValidationResultsTab = Tab(Text("Validation Results"), "/validation-results")
  val ValidationDetailsTab = Tab(Text("Validation Details"), "/validation-details")
  val UserPreferencesTab = Tab(<img src="/images/cogs.png" width="15" height="17" alt="Settings"/>, "/user-preferences")

  def visibleTabs = Seq(HomeTab, TrustAnchorsTab, RoasTab, FiltersTab, WhitelistTab, BgpPreviewTab, ExportTab, RtrSessionsTab, UserPreferencesTab)
}
