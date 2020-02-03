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
package org.hyperledger.besu.ethereum.privacy;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPOutput;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class OnChainPrivacyController {

  private final Blockchain blockchain;
  private final PrivateStateStorage privateStateStorage;
  private final PrivacyController privacyController;

  public OnChainPrivacyController(
      final Blockchain blockchain,
      final PrivateStateStorage privateStateStorage,
      final PrivacyController privacyController) {
    this.blockchain = blockchain;
    this.privateStateStorage = privateStateStorage;
    this.privacyController = privacyController;
  }

  public List<PrivateTransactionMetadata> buildTransactionMetadataList(
      final Bytes32 privacyGroupId) {
    final List<PrivateTransactionMetadata> pmtHashes = new ArrayList<>();
    PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage
            .getPrivacyGroupHeadBlockMap(blockchain.getChainHeadHash())
            .orElse(PrivacyGroupHeadBlockMap.EMPTY);
    if (privacyGroupHeadBlockMap.get(privacyGroupId) != null) {
      Hash blockHash = privacyGroupHeadBlockMap.get(privacyGroupId);
      while (blockHash != null) {
        pmtHashes.addAll(
            0,
            privateStateStorage
                .getPrivateBlockMetadata(blockHash, privacyGroupId)
                .get()
                .getPrivateTransactionMetadataList());
        blockHash = blockchain.getBlockHeader(blockHash).get().getParentHash();
        privacyGroupHeadBlockMap =
            privateStateStorage
                .getPrivacyGroupHeadBlockMap(blockHash)
                .orElse(PrivacyGroupHeadBlockMap.EMPTY);
        if (privacyGroupHeadBlockMap.get(privacyGroupId) != null) {
          blockHash = privacyGroupHeadBlockMap.get(privacyGroupId);
        } else {
          break;
        }
      }
    }
    return pmtHashes;
  }

  public List<PrivateTransactionWithMetadata> retrievePrivateTransactions(
      final List<PrivateTransactionMetadata> privateTransactionMetadataList,
      final String enclavePublicKey) {
    final ArrayList<PrivateTransactionWithMetadata> privateTransactions = new ArrayList<>();
    privateTransactionMetadataList.forEach(
        h -> {
          final Transaction privateMarkerTransaction =
              blockchain.getTransactionByHash(h.getPrivacyMarkerTransactionHash()).orElseThrow();
          final ReceiveResponse receiveResponse =
              privacyController.retrieveTransaction(
                  privateMarkerTransaction.getPayload().toBase64String(), enclavePublicKey);
          final BytesValueRLPInput input =
              new BytesValueRLPInput(
                  Bytes.fromBase64String(new String(receiveResponse.getPayload(), UTF_8)), false);

          privateTransactions.add(
              new PrivateTransactionWithMetadata(PrivateTransaction.readFrom(input), h));
        });
    return privateTransactions;
  }

  public Bytes serializeAddToGroupPayload(
      final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {

    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();
    rlpOutput.startList();
    privateTransactionWithMetadataList.forEach(
        privateTransactionWithMetadata -> privateTransactionWithMetadata.writeTo(rlpOutput));
    rlpOutput.endList();

    return rlpOutput.encoded();
  }

  public List<PrivateTransactionWithMetadata> deserializeAddToGroupPayload(
      final Bytes encodedAddToGroupPayload) {
    final ArrayList<PrivateTransactionWithMetadata> deserializedResponse = new ArrayList<>();
    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(encodedAddToGroupPayload, false);
    final int noOfEntries = bytesValueRLPInput.enterList();
    for (int i = 0; i < noOfEntries; i++) {
      deserializedResponse.add(PrivateTransactionWithMetadata.readFrom(bytesValueRLPInput));
    }
    bytesValueRLPInput.leaveList();
    return deserializedResponse;
  }
}
