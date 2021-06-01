package org.hyperledger.besu.pki;

import org.hyperledger.besu.pki.keystore.KeyStoreWrapper;
import org.hyperledger.besu.pki.keystore.SoftwareKeyStoreWrapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyStoreSupplier {

  private static final Logger LOG = LogManager.getLogger();

  public static PkiConfiguration PKI_CONFIG;
  public static KeyStoreWrapper KEYSTORE;
  public static KeyStoreWrapper TRUSTSTORE;

  public static void load(final PkiConfiguration configuration) {
    PKI_CONFIG = configuration;

    try {
      KEYSTORE =
          new SoftwareKeyStoreWrapper(
              configuration.getKeyStoreType(),
              configuration.getKeyStorePath(),
              configuration.getKeyStorePassword());
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
              configuration.getTrustStorePassword());
      LOG.info("Truststore initialized successfully!");
    } catch (Exception e) {
      LOG.error("Error initializing PKI Integration!");
      throw new RuntimeException("Error initializing PKI Integration", e);
    }
  }
}
