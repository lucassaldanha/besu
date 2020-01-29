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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;
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

  public List<Hash> buildTransactionList(final Bytes32 privacyGroupId) {
    final List<Hash> pmtHashes = new ArrayList<>();
    PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage
            .getPrivacyGroupHeadBlockMap(blockchain.getChainHeadHash())
            .orElse(PrivacyGroupHeadBlockMap.EMPTY);
    if (privacyGroupHeadBlockMap.get(privacyGroupId) != null) {
      Hash blockHash = privacyGroupHeadBlockMap.get(privacyGroupId);
      while (blockHash != null) {
        pmtHashes.addAll(
            0,
            privateStateStorage.getPrivateBlockMetadata(blockHash, privacyGroupId).get()
                .getPrivateTransactionMetadataList().stream()
                .map(PrivateTransactionMetadata::getPrivacyMarkerTransactionHash)
                .collect(Collectors.toList()));
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
    return Lists.reverse(pmtHashes);
  }

  public List<PrivateTransaction> retrievePrivateTransactions(
      final List<Hash> privateMarkerTransactionHashes, final String enclavePublicKey) {
    final ArrayList<PrivateTransaction> privateTransactions = new ArrayList<>();
    privateMarkerTransactionHashes.forEach(
        h -> {
          final Transaction privateMarkerTransaction =
              blockchain.getTransactionByHash(h).orElseThrow();
          final ReceiveResponse receiveResponse =
              privacyController.retrieveTransaction(
                  privateMarkerTransaction.getPayload().toBase64String(), enclavePublicKey);
          final BytesValueRLPInput input =
              new BytesValueRLPInput(
                  Bytes.fromBase64String(new String(receiveResponse.getPayload(), UTF_8)), false);

          privateTransactions.add(PrivateTransaction.readFrom(input));
        });
    return privateTransactions;
  }

  public Bytes serializeAddToGroupPayload(
      final List<Hash> privacyMarkerTransactionHashes,
      final List<PrivateTransaction> privateTransactions) {
    if (privacyMarkerTransactionHashes.size() != privateTransactions.size()) {
      throw new RuntimeException();
    }

    final BytesValueRLPOutput rlpOutput = new BytesValueRLPOutput();
    rlpOutput.startList();
    for (int i = 0; i < privacyMarkerTransactionHashes.size(); ++i) {
      final Hash hash = privacyMarkerTransactionHashes.get(i);
      final PrivateTransaction privateTransaction = privateTransactions.get(i);
      rlpOutput.startList();
      rlpOutput.writeBytes(hash);
      privateTransaction.writeTo(rlpOutput);
      rlpOutput.endList();
    }
    rlpOutput.endList();

    return rlpOutput.encoded();
  }

  public Map<Hash, PrivateTransaction> deserializeAddToGroupPayload(
      final Bytes encodedAddToGroupPayload) {
    final HashMap<Hash, PrivateTransaction> deserializedResponse = new HashMap<>();
    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(encodedAddToGroupPayload, false);
    final int noOfEntries = bytesValueRLPInput.enterList();
    for (int i = 0; i < noOfEntries; i++) {
      bytesValueRLPInput.enterList();
      final Hash privacyMarkerTransactionHash = Hash.wrap(bytesValueRLPInput.readBytes32());
      final PrivateTransaction privateTransaction =
          PrivateTransaction.readFrom(bytesValueRLPInput.readAsRlp());
      deserializedResponse.put(privacyMarkerTransactionHash, privateTransaction);
      bytesValueRLPInput.leaveList();
    }
    bytesValueRLPInput.leaveList();
    return deserializedResponse;
  }
}
