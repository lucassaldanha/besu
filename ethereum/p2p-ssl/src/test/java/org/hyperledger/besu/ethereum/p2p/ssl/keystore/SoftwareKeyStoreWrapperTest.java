/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.p2p.ssl.keystore;

import org.hyperledger.besu.ethereum.p2p.ssl.CryptoRuntimeException;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collection;

import org.junit.runners.Parameterized;

public class SoftwareKeyStoreWrapperTest extends BaseKeyStoreWrapperTest {

  private static final String PKCS12 = "PKCS12";
  private static final String JKS = "JKS";
  private static final String p12KeyStore = "/keys/partner1client1/partner1client1.p12";
  private static final String jksKeyStore = "/keys/partner1client1/partner1client1.jks";
  private static final String trustStore = "/keys/partner1client1/partner1client1-truststore.jks";
  private static final String validKeystorePassword = "test123";

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {
            "SoftwareKeyStoreWrapper[PKCS12 keystore only]",
            false,
            getPKCS12SoftwareKeyStoreWrapper()
          },
          {
            "SoftwareKeyStoreWrapper[JKS keystore only]",
            false,
            getJKSSoftwareKeyStoreWrapper(false)
          },
          {
            "SoftwareKeyStoreWrapper[JKS keystore/truststore]",
            true,
            getJKSSoftwareKeyStoreWrapper(true)
          }
        });
  }

  private static KeyStoreWrapper getPKCS12SoftwareKeyStoreWrapper() {
    try {
      return new SoftwareKeyStoreWrapper(PKCS12, toPath(p12KeyStore), validKeystorePassword);
    } catch (final Exception e) {
      throw new CryptoRuntimeException("Failed to initialize software keystore", e);
    }
  }

  private static KeyStoreWrapper getJKSSoftwareKeyStoreWrapper(final boolean setupTruststore) {
    try {
      final Path keystoreLocation = toPath(jksKeyStore);
      if (setupTruststore) {
        final Path truststoreLocation = toPath(trustStore);
        // password shouldn't be needed for retrieving certificate from truststore
        return new SoftwareKeyStoreWrapper(
            JKS, keystoreLocation, validKeystorePassword, JKS, truststoreLocation, null);
      }
      return new SoftwareKeyStoreWrapper(JKS, keystoreLocation, validKeystorePassword);
    } catch (final Exception e) {
      throw new CryptoRuntimeException("Failed to initialize software keystore", e);
    }
  }
}
