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

import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;

public class PrivateStateRehydration {

  private static final Logger LOG = LogManager.getLogger();

  private final PrivateStateStorage privateStateStorage;
  private final Blockchain blockchain;
  private final ProtocolSchedule<?> protocolSchedule;
  private final WorldStateArchive publicWorldStateArchive;

  public PrivateStateRehydration(
      final PrivateStateStorage privateStateStorage,
      final Blockchain blockchain,
      final ProtocolSchedule<?> protocolSchedule,
      final WorldStateArchive publicWorldStateArchive) {
    this.privateStateStorage = privateStateStorage;
    this.blockchain = blockchain;
    this.protocolSchedule = protocolSchedule;
    this.publicWorldStateArchive = publicWorldStateArchive;
  }

  public void rehydrate(
      final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {
    final long rehydrationStartTimestamp = System.currentTimeMillis();
    final long chainHeadBlockNumber = blockchain.getChainHeadBlockNumber();
    final Bytes32 privacyGroupId =
        Bytes32.wrap(
            privateTransactionWithMetadataList
                .get(0)
                .getPrivateTransaction()
                .getPrivacyGroupId()
                .orElseThrow());

    LOG.info("Rehydrating privacy group...");

    long lastBlockNumber = -1;
    for (int i = 0; i < privateTransactionWithMetadataList.size(); i++) {
      // find out which block this transaction is in
      Hash blockhash = getBlockHashForIndex(i, privateTransactionWithMetadataList);

      //      // create a list with all the private transactions from
      // privateTransactionWithMetadataList
      //      // that are in this block
      //      List<Hash> pmtHashesForTheNewGroupInThisBlock = new ArrayList<>();
      //      pmtHashesForTheNewGroupInThisBlock.add(
      //          privateTransactionWithMetadataList
      //              .get(i)
      //              .getPrivateTransactionMetadata()
      //              .getPrivacyMarkerTransactionHash());
      //      if (i < privateTransactionWithMetadataList.size() - 1) {
      //        while (blockhash.equals(getBlockHashForIndex(i + 1,
      // privateTransactionWithMetadataList))) {
      //          i++;
      //          pmtHashesForTheNewGroupInThisBlock.add(
      //              privateTransactionWithMetadataList
      //                  .get(i)
      //                  .getPrivateTransactionMetadata()
      //                  .getPrivacyMarkerTransactionHash());
      //        }
      //      }

      final Block block = blockchain.getBlockByHash(blockhash).orElseThrow(RuntimeException::new);
      final Hash blockHash = block.getHash();
      final BlockHeader blockHeader = block.getHeader();
      LOG.info(
          "Processing block {} ({}/{}), {}",
          blockHash,
          blockHeader.getNumber(),
          chainHeadBlockNumber,
          block.getBody().getTransactions().stream()
              .map(Transaction::getHash)
              .collect(Collectors.toList()));

      final List<Transaction> allTransactions = block.getBody().getTransactions();

      final ProtocolSpec<?> protocolSpec =
          protocolSchedule.getByBlockNumber(blockchain.getBlockHeader(blockHash).get().getNumber());
      final PrivateGroupRehydrationBlockProcessor privateGroupRehydrationBlockProcessor =
          new PrivateGroupRehydrationBlockProcessor(
              protocolSpec.getTransactionProcessor(),
              protocolSpec.getTransactionReceiptFactory(),
              protocolSpec.getBlockReward(),
              protocolSpec.getMiningBeneficiaryCalculator(),
              protocolSpec.isSkipZeroBlockRewards());

      final MutableWorldState publicWorldState =
          blockchain
              .getBlockHeader(blockHeader.getParentHash())
              .map(BlockHeader::getStateRoot)
              .flatMap(publicWorldStateArchive::getMutable)
              .orElseThrow(RuntimeException::new);

      privateGroupRehydrationBlockProcessor.processBlock(
          blockchain, publicWorldState, blockHeader, allTransactions, block.getBody().getOmmers());

      if (lastBlockNumber == -1) {
        lastBlockNumber = blockHeader.getNumber();
      }

      long blockNumber = blockHeader.getNumber();
      if (blockNumber - lastBlockNumber > 1) {
        rehydratePrivacyGroupHeadBlockMap(privacyGroupId, blockchain, lastBlockNumber, blockNumber);
      }
    }
    rehydratePrivacyGroupHeadBlockMap(
        privacyGroupId, blockchain, lastBlockNumber, chainHeadBlockNumber);
    final long rehydrationDuration = System.currentTimeMillis() - rehydrationStartTimestamp;
    LOG.info("Rehydration took {} seconds", rehydrationDuration / 1000.0);
  }

  protected void rehydratePrivacyGroupHeadBlockMap(
      final Bytes32 privacyGroupId,
      final Blockchain currentBlockchain,
      final long from,
      final long to) {
    for (long j = from + 1; j < to; j++) {
      final BlockHeader theBlockHeader = currentBlockchain.getBlockHeader(j).orElseThrow();
      final PrivacyGroupHeadBlockMap thePrivacyGroupHeadBlockMap =
          privateStateStorage
              .getPrivacyGroupHeadBlockMap(theBlockHeader.getHash())
              .orElse(PrivacyGroupHeadBlockMap.EMPTY);
      final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();
      thePrivacyGroupHeadBlockMap.put(
          Bytes32.wrap(privacyGroupId), currentBlockchain.getBlockHeader(from).get().getHash());
      privateStateUpdater.putPrivacyGroupHeadBlockMap(
          theBlockHeader.getHash(), new PrivacyGroupHeadBlockMap(thePrivacyGroupHeadBlockMap));
      privateStateUpdater.commit();
    }
  }

  private Hash getBlockHashForIndex(
      final int i, final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {
    return blockchain
        .getTransactionLocation(
            privateTransactionWithMetadataList
                .get(i)
                .getPrivateTransactionMetadata()
                .getPrivacyMarkerTransactionHash())
        .get()
        .getBlockHash();
  }
}
