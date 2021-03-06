package br.rnp.stcfed.sts.client.impl;

/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright 1997-2008 Sun Microsystems, Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms of either the GNU
 * General Public License Version 2 only ("GPL") or the Common Development
 * and Distribution License("CDDL") (collectively, the "License").  You
 * may not use this file except in compliance with the License. You can obtain
 * a copy of the License at https://glassfish.dev.java.net/public/CDDL+GPL.html
 * or glassfish/bootstrap/legal/LICENSE.txt.  See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * When distributing the software, include this License Header Notice in each
 * file and include the License file at glassfish/bootstrap/legal/LICENSE.txt.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.  If applicable, add the following below the License
 * Header, with the fields enclosed by brackets [] replaced by your own
 * identifying information: "Portions Copyrighted [year]
 * [name of copyright owner]"
 *
 * Contributor(s):
 *
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding "[Contributor]
 * elects to include this software in this distribution under the [CDDL or GPL
 * Version 2] license."  If you don't indicate a single choice of license, a
 * recipient has the option to distribute your version of this file under
 * either the CDDL, the GPL Version 2 or to extend the choice of license to
 * its licensees as provided above.  However, if you add GPL Version 2 code
 * and therefore, elected the GPL Version 2 license, then the option applies
 * only if the new code is made subject to such option by the copyright
 * holder.
 */



/*
 * UsernamePasswordCallbackHandler.java
 *
 * Created on June 17, 2006, 11:50 PM
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class UsernamePasswordCallbackHandler implements CallbackHandler {

    private static final Log log = LogFactory.getLog(UsernamePasswordCallbackHandler.class);

    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        System.out.println(" ===== UsernamePasswordCallbackHandler =======");
        log.info("  ----> Checking callbacks");
        for (int i=0; i < callbacks.length; i++) {
            Callback callback = callbacks[i];
            log.info("  ----> STS Callback" + callback);
            if (callback instanceof NameCallback) {
                handleUsernameCallback((NameCallback)callback);
            } else if (callback instanceof PasswordCallback) {
                handlePasswordCallback((PasswordCallback)callback);
            }else{
                throw new UnsupportedCallbackException(callback, "Unknow callback for username or password");
            }
        }
    }

    private void handleUsernameCallback(NameCallback cb)throws IOException{
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy K:mm:ss,S");
        System.out.println(sdf.format(new Date()));
        log.info("  ----> Setting username for the STS");
        cb.setName("stsUser");
    }

    private void handlePasswordCallback(PasswordCallback cb)throws IOException{
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy K:mm:ss,S");
        System.out.println(sdf.format(new Date()));
        log.info("  ----> Setting password for the STS");
        cb.setPassword("stsPassword".toCharArray());
    }
}
