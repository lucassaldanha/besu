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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSchedule;
import org.hyperledger.besu.ethereum.mainnet.ProtocolSpec;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.migration.PrivateStorageMigrationException;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class PrivateStateRehydration {

    private static final Logger LOG = LogManager.getLogger();

    private final PrivateStateStorage privateStateStorage;
    private final Blockchain blockchain;
    private final Address onchainPrivacyPrecompileAddress;
    private final ProtocolSchedule<?> protocolSchedule;
    private final WorldStateArchive publicWorldStateArchive;

    public PrivateStateRehydration(
            final PrivateStateStorage privateStateStorage,
            final Blockchain blockchain,
            final Address onchainPrivacyPrecompileAddress,
            final ProtocolSchedule<?> protocolSchedule,
            final WorldStateArchive publicWorldStateArchive) {
        this.privateStateStorage = privateStateStorage;
        this.blockchain = blockchain;
        this.onchainPrivacyPrecompileAddress = onchainPrivacyPrecompileAddress;
        this.protocolSchedule = protocolSchedule;
        this.publicWorldStateArchive = publicWorldStateArchive;
    }

    public void rehydrate(List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {
        final long rehydrationStartTimestamp = System.currentTimeMillis();
        final long chainHeadBlockNumber = blockchain.getChainHeadBlockNumber();

        LOG.info("Rehydrating privacy group...");


        for (int i = 0; i < privateTransactionWithMetadataList.size(); i++) {
            // find out which block this transaction is in
            Hash blockhash = getBlockHashForIndex(i, privateTransactionWithMetadataList);

            // create a list with all the private transactions from privateTransactionWithMetadataList that are in this block
            List<Hash> pmtHashesForTheNewGroupInThisBlock = new ArrayList<>();
            pmtHashesForTheNewGroupInThisBlock.add(privateTransactionWithMetadataList.get(i).getPrivateTransactionMetadata().getPrivacyMarkerTransactionHash());
            while (blockhash.equals(getBlockHashForIndex(i + 1, privateTransactionWithMetadataList))) {
                i++;
                pmtHashesForTheNewGroupInThisBlock.add(privateTransactionWithMetadataList.get(i).getPrivateTransactionMetadata().getPrivacyMarkerTransactionHash())
            }

            final Block block =
                    blockchain
                            .getBlockByHash(blockhash)
                            .orElseThrow(RuntimeException::new);
            final Hash blockHash = block.getHash();
            final BlockHeader blockHeader = block.getHeader();
            LOG.info("Processing block {} ({}/{})", blockHash, block.getHeader(), chainHeadBlockNumber);

            final List<Transaction> pmtsInBlock = findPMTsInBlock(block);

            // from the pmtsInBlock remove the ones that are in ptxForTheNewGroupInThisBlock
            for (int j = 0; j < pmtsInBlock.size(); j++) {
                if (pmtHashesForTheNewGroupInThisBlock.contains(pmtsInBlock.get(j).getHash())) {
                    pmtsInBlock.remove(j);
                }
            }

            final List<Transaction> allTransactions = block.getBody().getTransactions();

            // truncate list of transactions up to last transaction in ptxForTheNewGroupInThisBlock
            final Hash lastPmtHash = pmtsInBlock.get(pmtsInBlock.size() - 1).getHash();
            final int transactionIndex = blockchain.getTransactionLocation(lastPmtHash).get().getTransactionIndex();
            final List<Transaction> transactionsToExecute = allTransactions.subList(0, transactionIndex);

            // remove all the transactions remaining in pmtsInBlock from the transactions list
            for (int j = 0; j < transactionsToExecute.size(); j++) {
                if (pmtsInBlock.contains(transactionsToExecute.get(j))) {
                    transactionsToExecute.remove(j);
                }
            }

            // ? if there is no group head block map create an empty one. Every block should have one of these maps !?!?!?
            // This should not be necessary: createPrivacyGroupHeadBlockMap(blockHeader);

            final ProtocolSpec<?> protocolSpec = protocolSchedule.getByBlockNumber(blockchain.getBlockHeader(blockHash).get().getNumber());
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
                    blockchain, publicWorldState, blockHeader, transactionsToExecute, block.getBody().getOmmers());
        }

        final long rehydrationDuration = System.currentTimeMillis() - rehydrationStartTimestamp;
        LOG.info("Migration took {} seconds", rehydrationDuration / 1000.0);
    }

    private void createPrivacyGroupHeadBlockMap(final BlockHeader blockHeader) {
        final PrivacyGroupHeadBlockMap privacyGroupHeadBlockHash =
                new PrivacyGroupHeadBlockMap(
                        privateStateStorage
                                .getPrivacyGroupHeadBlockMap(blockHeader.getParentHash())
                                .orElse(PrivacyGroupHeadBlockMap.EMPTY));

        privateStateStorage
                .updater()
                .putPrivacyGroupHeadBlockMap(blockHeader.getHash(), privacyGroupHeadBlockHash)
                .commit();
    }

    private List<Transaction> findPMTsInBlock(final Block block) {
        return block.getBody().getTransactions().stream()
                .filter(tx -> tx.getTo().isPresent() && tx.getTo().get().equals(onchainPrivacyPrecompileAddress))
                .collect(Collectors.toList());
    }

    private Hash getBlockHashForIndex(final int i, final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList) {
        return blockchain.getTransactionLocation(privateTransactionWithMetadataList.get(i).getPrivateTransactionMetadata().getPrivacyMarkerTransactionHash()).get().getBlockHash();
    }
}
