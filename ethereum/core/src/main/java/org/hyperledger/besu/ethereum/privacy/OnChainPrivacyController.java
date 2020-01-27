package org.hyperledger.besu.ethereum.privacy;

import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.tuweni.bytes.Bytes32;

public class OnChainPrivacyController {

  private final PrivateStateStorage privateStateStorage;
  private final Blockchain blockchain;

  public OnChainPrivacyController(
      final Blockchain blockchain, final PrivateStateStorage privateStateStorage) {
    this.blockchain = blockchain;
    this.privateStateStorage = privateStateStorage;
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
    return pmtHashes;
  }
}
