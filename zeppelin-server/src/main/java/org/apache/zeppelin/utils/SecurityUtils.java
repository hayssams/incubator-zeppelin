/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.zeppelin.utils;

import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.subject.Subject;
import org.apache.zeppelin.conf.ZeppelinConfiguration;
import org.apache.zeppelin.socket.Message;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * Tools for securing Zeppelin
 */
public class SecurityUtils {

  public static Boolean isValidOrigin(String sourceHost, ZeppelinConfiguration conf)
      throws UnknownHostException, URISyntaxException {
    if (sourceHost == null || sourceHost.isEmpty()){
      return false;
    }
    String sourceUriHost = new URI(sourceHost).getHost();
    sourceUriHost = (sourceUriHost == null) ? "" : sourceUriHost.toLowerCase();

    sourceUriHost = sourceUriHost.toLowerCase();
    String currentHost = InetAddress.getLocalHost().getHostName().toLowerCase();

    return conf.getAllowedOrigins().contains("*") ||
            currentHost.equals(sourceUriHost) ||
            "localhost".equals(sourceUriHost) ||
            conf.getAllowedOrigins().contains(sourceHost);
  }

  /**
   * Return the authenticated user if any otherwise returns "anonymous"
   * @return shiro principal
   */
  public static String getPrincipal() {
    Subject subject = org.apache.shiro.SecurityUtils.getSubject();
    String principal;
    if (subject.isAuthenticated()) {
      principal = subject.getPrincipal().toString();
    }
    else {
      principal = "anonymous";
    }
    return principal;
  }

  /**
   * Permision object types
   */
  public enum TYPE {
    INTERPERTERS,
    INTERPRETER,
    NOTES,
    NOTE
  }

  /**
   * Check operation is allowed on this object instanc eofr the current subject
   * @param cls : Object Type
   * @param op : Operation
   * @param instance : the object being accessed
   */
  public static void checkPermission(TYPE cls, Message.OP op, String instance) {
    if (!isPermitted(cls, op, instance)) {
      throw new UnauthorizedException("");
    }
  }

  public static void checkPermission(TYPE cls, Message.OP op) {
    checkPermission(cls, op, "*");
  }

  public static boolean isPermitted(TYPE cls, Message.OP op, String instance) {
    Subject currentUser = org.apache.shiro.SecurityUtils.getSubject();
    return currentUser.isPermitted(String.format("%s:%s:%s", cls.toString(), op.toString(), instance));
  }

  public static boolean isPermitted(TYPE cls, Message.OP op) {
    return isPermitted(cls, op, "*");
  }
}
