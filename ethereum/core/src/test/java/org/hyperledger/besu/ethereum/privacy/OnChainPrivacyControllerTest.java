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

import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;

import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class OnChainPrivacyControllerTest {

  private static final String ENCLAVE_PUBLIC_KEY = "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=";
  private static final String PRIVACY_GROUP_ID = "DyAOiF/ynpc+JXa2YAGB0bCitSlOMNm+ShmB/7M6C4w=";

  private OnChainPrivacyController onChainPrivacyController;
  private Blockchain blockchain;
  private PrivateStateStorage privateStateStorage;

  @Before
  public void setUp() {
    blockchain = mock(Blockchain.class);
    privateStateStorage = mock(PrivateStateStorage.class);

    onChainPrivacyController = new OnChainPrivacyController(blockchain, privateStateStorage);
  }

  @Test
  public void buildsEmptyTransactionListWhenNoGroupIsTracked() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(Optional.empty());
    final List<Hash> privacyGroupMarkerTransactions =
        onChainPrivacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(0);
  }

  @Test
  public void buildsEmptyTransactionListWhenRequestedGroupIsNotTracked() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(
            Optional.of(
                new PrivacyGroupHeadBlockMap(
                    singletonMap(
                        Bytes32.wrap(Bytes.fromBase64String(ENCLAVE_PUBLIC_KEY)), Hash.ZERO))));
    final List<Hash> privacyGroupMarkerTransactions =
        onChainPrivacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(0);
    verify(privateStateStorage).getPrivacyGroupHeadBlockMap(Hash.ZERO);
  }

  @Test
  public void buildsTransactionListWhenRequestedGroupHasTransaction() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(
            Optional.of(
                new PrivacyGroupHeadBlockMap(
                    singletonMap(
                        Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)), Hash.ZERO))));
    when(privateStateStorage.getPrivateBlockMetadata(any(Bytes32.class), any(Bytes32.class)))
        .thenReturn(
            Optional.of(
                new PrivateBlockMetadata(
                    singletonList(new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO)))));
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(null));
    final List<Hash> privacyGroupMarkerTransactions =
        onChainPrivacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(1);
    assertThat(privacyGroupMarkerTransactions.get(0)).isEqualTo(Hash.ZERO);
    verify(privateStateStorage).getPrivacyGroupHeadBlockMap(Hash.ZERO);
    verify(privateStateStorage)
        .getPrivateBlockMetadata(
            any(Bytes32.class), eq(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID))));
  }

  @SuppressWarnings("unchecked")
  @Test
  public void buildsTransactionListWhenRequestedGroupHasTransactions() {
    when(blockchain.getChainHeadHash()).thenReturn(Hash.ZERO);
    final Optional<PrivacyGroupHeadBlockMap> privacyGroupHeadBlockMap =
        Optional.of(
            new PrivacyGroupHeadBlockMap(
                singletonMap(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)), Hash.ZERO)));
    final Optional<PrivateBlockMetadata> privateBlockMetadata =
        Optional.of(
            new PrivateBlockMetadata(
                singletonList(new PrivateTransactionMetadata(Hash.ZERO, Hash.ZERO))));
    when(privateStateStorage.getPrivacyGroupHeadBlockMap(any(Hash.class)))
        .thenReturn(privacyGroupHeadBlockMap, privacyGroupHeadBlockMap, Optional.empty());
    when(privateStateStorage.getPrivateBlockMetadata(any(Bytes32.class), any(Bytes32.class)))
        .thenReturn(privateBlockMetadata, privateBlockMetadata);
    when(blockchain.getBlockHeader(any(Hash.class)))
        .thenReturn(buildBlockHeaderWithParentHash(Hash.ZERO));

    final List<Hash> privacyGroupMarkerTransactions =
        onChainPrivacyController.buildTransactionList(
            Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID)));

    assertThat(privacyGroupMarkerTransactions.size()).isEqualTo(2);
    assertThat(privacyGroupMarkerTransactions.get(0)).isEqualTo(Hash.ZERO);
    assertThat(privacyGroupMarkerTransactions.get(1)).isEqualTo(Hash.ZERO);
    verify(privateStateStorage, times(3)).getPrivacyGroupHeadBlockMap(Hash.ZERO);
    verify(privateStateStorage, times(2))
        .getPrivateBlockMetadata(
            any(Bytes32.class), eq(Bytes32.wrap(Bytes.fromBase64String(PRIVACY_GROUP_ID))));
  }

  @NotNull
  private Optional<BlockHeader> buildBlockHeaderWithParentHash(final Hash parentHash) {
    return Optional.of(
        new BlockHeader(
            parentHash, null, null, null, null, null, null, null, 0, 0, 0, 0, null, null, 0, null));
  }
}
