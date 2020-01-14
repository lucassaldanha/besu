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
package org.hyperledger.besu.ethereum.privacy.storage;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.hyperledger.besu.ethereum.privacy.PrivateTransactionReceipt;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorage;
import org.hyperledger.besu.plugin.services.storage.KeyValueStorageTransaction;

import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class PrivateStateKeyValueStorage implements PrivateStateStorage {

  private static final Bytes TX_RECEIPT_SUFFIX = Bytes.of("RECEIPT".getBytes(UTF_8));
  private static final Bytes METADATA_KEY_SUFFIX = Bytes.of("METADATA".getBytes(UTF_8));
  private static final Bytes PRIVACY_GROUP_HEAD_BLOCK_MAP_SUFFIX =
      Bytes.of("PGHEADMAP".getBytes(UTF_8));

  private final KeyValueStorage keyValueStorage;

  public PrivateStateKeyValueStorage(final KeyValueStorage keyValueStorage) {
    this.keyValueStorage = keyValueStorage;
  }

  @Override
  public Optional<PrivateTransactionReceipt> getTransactionReceipt(final Bytes blockHashTxHash) {
    return get(blockHashTxHash, TX_RECEIPT_SUFFIX)
        .map(b -> PrivateTransactionReceipt.readFrom(new BytesValueRLPInput(b, false)));
  }

  @Override
  public Optional<PrivateBlockMetadata> getPrivateBlockMetadata(
      final Bytes32 blockHash, final Bytes32 privacyGroupId) {
    return get(Bytes.concatenate(blockHash, privacyGroupId), METADATA_KEY_SUFFIX)
        .map(this::rlpDecodePrivateBlockMetadata);
  }

  @Override
  public Optional<PrivacyGroupHeadBlockMap> getPrivacyGroupHeadBlockMap(final Bytes32 blockHash) {
    return get(blockHash, PRIVACY_GROUP_HEAD_BLOCK_MAP_SUFFIX)
        .map(b -> PrivacyGroupHeadBlockMap.readFrom(new BytesValueRLPInput(b, false)));
  }

  @Override
  public boolean isPrivateStateAvailable(final Bytes32 transactionHash) {
    return false;
  }

  @Override
  public boolean isWorldStateAvailable(final Bytes32 rootHash) {
    return false;
  }

  private Optional<Bytes> get(final Bytes key, final Bytes keySuffix) {
    return keyValueStorage.get(Bytes.concatenate(key, keySuffix).toArrayUnsafe()).map(Bytes::wrap);
  }

  private PrivateBlockMetadata rlpDecodePrivateBlockMetadata(final Bytes bytes) {
    return PrivateBlockMetadata.readFrom(RLP.input(bytes));
  }

  @Override
  public PrivateStateStorage.Updater updater() {
    return new PrivateStateKeyValueStorage.Updater(keyValueStorage.startTransaction());
  }

  public static class Updater implements PrivateStateStorage.Updater {

    private final KeyValueStorageTransaction transaction;

    private Updater(final KeyValueStorageTransaction transaction) {
      this.transaction = transaction;
    }

    @Override
    public PrivateStateStorage.Updater putTransactionReceipt(
        final Bytes blockHashTransactionHash, final PrivateTransactionReceipt receipt) {
      set(blockHashTransactionHash, TX_RECEIPT_SUFFIX, RLP.encode(receipt::writeTo));
      return this;
    }

    @Override
    public Updater putPrivateBlockMetadata(
        final Bytes32 blockHash,
        final Bytes32 privacyGroupId,
        final PrivateBlockMetadata metadata) {
      set(
          Bytes.concatenate(blockHash, privacyGroupId),
          METADATA_KEY_SUFFIX,
          RLP.encode(metadata::writeTo));
      return this;
    }

    @Override
    public PrivateStateStorage.Updater putPrivacyGroupHeadBlockMap(
        final Bytes32 blockHash, final PrivacyGroupHeadBlockMap map) {
      set(blockHash, PRIVACY_GROUP_HEAD_BLOCK_MAP_SUFFIX, RLP.encode(map::writeTo));
      return this;
    }

    @Override
    public void commit() {
      transaction.commit();
    }

    @Override
    public void rollback() {
      transaction.rollback();
    }

    private void set(final Bytes key, final Bytes keySuffix, final Bytes value) {
      transaction.put(Bytes.concatenate(key, keySuffix).toArrayUnsafe(), value.toArrayUnsafe());
    }
  }
}
