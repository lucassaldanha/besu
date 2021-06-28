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

package org.hyperledger.besu.pki.config;

import org.hyperledger.besu.pki.keystore.KeyStoreWrapper;
import org.hyperledger.besu.pki.keystore.SoftwareKeyStoreWrapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyStoreSupplier {

  private static final Logger LOG = LogManager.getLogger();

  public static PkiBlockCreationConfiguration PKI_CONFIG;
  public static KeyStoreWrapper KEYSTORE;
  public static KeyStoreWrapper TRUSTSTORE;

  public static void load(final PkiBlockCreationConfiguration configuration) {
    PKI_CONFIG = configuration;

    try {
      KEYSTORE =
          new SoftwareKeyStoreWrapper(
              configuration.getKeyStoreType(),
              configuration.getKeyStorePath(),
              configuration.getKeyStorePassword(),
              null);
      LOG.info("Keystore loaded successfully!");
    } catch (Exception e) {
      LOG.error("Error initializing PKI Integration!");
      throw new RuntimeException("Error initializing PKI Integration", e);
    }

    try {
      TRUSTSTORE =
          new SoftwareKeyStoreWrapper(
              configuration.getTrustStoreType(),
              configuration.getTrustStorePath(),
              configuration.getTrustStorePassword(),
              null);
      LOG.info("Truststore initialized successfully!");
    } catch (Exception e) {
      LOG.error("Error initializing PKI Integration!");
      throw new RuntimeException("Error initializing PKI Integration", e);
    }
  }
}
