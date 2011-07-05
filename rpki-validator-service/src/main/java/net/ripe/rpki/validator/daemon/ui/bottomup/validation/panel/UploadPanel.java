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
package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import net.ripe.rpki.validator.daemon.ui.common.AbstractPanel;
import net.ripe.rpki.validator.daemon.ui.common.NavigationalCallbackHandler;
import org.apache.wicket.markup.html.form.Form;
import org.apache.wicket.markup.html.form.upload.FileUpload;
import org.apache.wicket.markup.html.form.upload.FileUploadField;
import org.apache.wicket.markup.html.panel.FeedbackPanel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.util.lang.Bytes;

public class UploadPanel extends AbstractPanel<FileUpload> {
    private static final long serialVersionUID = 6448751150586724591L;
    private static final int MAX_SIZE_IN_KB = 100;
    private Integer maxSize;

    private final NavigationalCallbackHandler<byte[]> callbackHandler;

    public UploadPanel(String id, NavigationalCallbackHandler<byte[]> callbackHandler) {
        this(id, MAX_SIZE_IN_KB, callbackHandler);
    }

    public UploadPanel(String id, Integer maxSize, NavigationalCallbackHandler<byte[]> callbackHandler) {
        super(id);

        this.maxSize = maxSize;
        this.callbackHandler = callbackHandler;

        Model<FileUpload> model = new Model<FileUpload>();
        setDefaultModel(model);

        initPanel(model);
    }

    private void initPanel(IModel<FileUpload> model) {
        add(new FeedbackPanel("feedbackPanel"));

        Form<FileUpload> form = new UploadForm("uploadForm");

        FileUploadField fileInput = new FileUploadField("fileInput", model);
        fileInput.setRequired(true);
        form.add(fileInput);

        add(form);
    }

    private class UploadForm extends Form<FileUpload> {

        private static final long serialVersionUID = 2215584856791846548L;

        public UploadForm(String id) {
            super(id);

            setMultiPart(true);
            setMaxSize(Bytes.kilobytes(maxSize));
        }

        @Override
        protected void onSubmit() {
            FileUpload fileUpload = UploadPanel.this.getPanelModelObject();

            byte[] bytes = fileUpload.getBytes();

            callbackHandler.callback(bytes);
        }
    }
}
