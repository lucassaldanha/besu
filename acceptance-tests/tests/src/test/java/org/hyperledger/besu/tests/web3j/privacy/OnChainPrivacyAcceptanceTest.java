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
package org.hyperledger.besu.tests.web3j.privacy;

import static org.assertj.core.api.Assertions.assertThat;

import org.hyperledger.besu.crypto.SecureRandomProvider;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.tests.acceptance.dsl.privacy.PrivacyAcceptanceTestBase;
import org.hyperledger.besu.tests.acceptance.dsl.privacy.PrivacyNode;
import org.hyperledger.besu.tests.acceptance.dsl.transaction.privacy.PrivacyRequestFactory.PrivxCreatePrivacyGroup;
import org.hyperledger.besu.tests.web3j.generated.EventEmitter;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;
import org.web3j.protocol.besu.response.privacy.PrivacyGroup;
import org.web3j.protocol.besu.response.privacy.PrivateTransactionReceipt;
import org.web3j.protocol.core.methods.response.Log;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.utils.Base64String;

public class OnChainPrivacyAcceptanceTest extends PrivacyAcceptanceTestBase {
  private static final long POW_CHAIN_ID = 2018;

  private PrivacyNode alice;
  private PrivacyNode bob;
  private PrivacyNode charlie;

  @Before
  public void setUp() throws Exception {
    alice =
        privacyBesu.createPrivateTransactionEnabledMinerNode(
            "node1", privacyAccountResolver.resolve(0), Address.PRIVACY);
    bob =
        privacyBesu.createPrivateTransactionEnabledNode(
            "node2", privacyAccountResolver.resolve(1), Address.PRIVACY);
    charlie =
        privacyBesu.createPrivateTransactionEnabledNode(
            "node3", privacyAccountResolver.resolve(2), Address.PRIVACY);
    privacyCluster.start(alice, bob, charlie);
  }

  @Test
  public void nodeCanCreatePrivacyGroup() {
    final PrivxCreatePrivacyGroup privxCreatePrivacyGroup =
        alice.execute(privacyTransactions.createOnChainPrivacyGroup(alice, alice, bob));

    assertThat(privxCreatePrivacyGroup).isNotNull();

    final PrivacyGroup expectedGroup =
        new PrivacyGroup(
            privxCreatePrivacyGroup.getPrivacyGroupId(),
            PrivacyGroup.Type.PANTHEON,
            "",
            "",
            Base64String.wrapList(alice.getEnclaveKey(), bob.getEnclaveKey()));

    alice.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));

    bob.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));

    final String rlpParticipants =
        alice.execute(
            privateContractTransactions.callOnChainPermissioningSmartContract(
                Address.PRIVACY_PROXY.toHexString(),
                "0x0b0235be" // get participants method signature
                    + Bytes.fromBase64String(alice.getEnclaveKey()).toUnprefixedHexString(),
                alice.getTransactionSigningKey(),
                POW_CHAIN_ID,
                alice.getEnclaveKey(),
                privxCreatePrivacyGroup.getPrivacyGroupId()));

    final PrivateTransactionReceipt expectedReceipt =
        new PrivateTransactionReceipt(
            null,
            "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
            "0x000000000000000000000000000000000000007c",
            "0x0000000000000000000000000000000000000000000000000000000000000020" // dynamic
                // array offset
                + "0000000000000000000000000000000000000000000000000000000000000002" // length
                // of array
                + Bytes.fromBase64String(alice.getEnclaveKey()).toUnprefixedHexString() // first
                // element
                + Bytes.fromBase64String(bob.getEnclaveKey()).toUnprefixedHexString(), // second
            // element
            Collections.emptyList(),
            null,
            null,
            "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=",
            null,
            privxCreatePrivacyGroup.getPrivacyGroupId(),
            "0x1",
            null);

    alice.verify(
        privateTransactionVerifier.validPrivateTransactionReceipt(
            rlpParticipants, expectedReceipt));

    bob.verify(
        privateTransactionVerifier.validPrivateTransactionReceipt(
            rlpParticipants, expectedReceipt));
  }

  @Test
  public void deployingMustGiveValidReceipt() {
    final SecureRandom secureRandom = SecureRandomProvider.createSecureRandom();
    final byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    final Bytes privacyGroupId = Bytes.wrap(bytes);

    final EventEmitter eventEmitter =
        alice.execute(
            privateContractTransactions.createSmartContractWithPrivacyGroupId(
                EventEmitter.class,
                alice.getTransactionSigningKey(),
                POW_CHAIN_ID,
                alice.getEnclaveKey(),
                privacyGroupId.toBase64String()));

    privateContractVerifier
        .validPrivateContractDeployed(
            eventEmitter.getContractAddress(), alice.getAddress().toString())
        .verify(eventEmitter);
  }

  @Test
  public void canAddParticipantToGroup() {
    final PrivxCreatePrivacyGroup privxCreatePrivacyGroup =
        alice.execute(privacyTransactions.createOnChainPrivacyGroup(alice, alice, bob));

    assertThat(privxCreatePrivacyGroup).isNotNull();

    final PrivacyGroup expectedGroup =
        new PrivacyGroup(
            privxCreatePrivacyGroup.getPrivacyGroupId(),
            PrivacyGroup.Type.PANTHEON,
            "",
            "",
            Base64String.wrapList(alice.getEnclaveKey(), bob.getEnclaveKey()));

    alice.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));

    bob.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));

    final EventEmitter eventEmitter =
        alice.execute(
            privateContractTransactions.createSmartContractWithPrivacyGroupId(
                EventEmitter.class,
                alice.getTransactionSigningKey(),
                POW_CHAIN_ID,
                alice.getEnclaveKey(),
                privxCreatePrivacyGroup.getPrivacyGroupId()));

    privateContractVerifier
        .validPrivateContractDeployed(
            eventEmitter.getContractAddress(), alice.getAddress().toString())
        .verify(eventEmitter);

    final String transactionHash =
        alice.execute(
            privacyTransactions.addToPrivacyGroup(
                privxCreatePrivacyGroup.getPrivacyGroupId(), alice, charlie));

    final PrivacyGroup expectedGroupAfterCharlieIsAdded =
        new PrivacyGroup(
            privxCreatePrivacyGroup.getPrivacyGroupId(),
            PrivacyGroup.Type.PANTHEON,
            "",
            "",
            Base64String.wrapList(
                alice.getEnclaveKey(), bob.getEnclaveKey(), charlie.getEnclaveKey()));

    alice.verify(
        privateTransactionVerifier.validOnChainPrivacyGroupExists(
            expectedGroupAfterCharlieIsAdded));

    bob.verify(
        privateTransactionVerifier.validOnChainPrivacyGroupExists(
            expectedGroupAfterCharlieIsAdded));

    charlie.verify(
        privateTransactionVerifier.validOnChainPrivacyGroupExists(
            expectedGroupAfterCharlieIsAdded));

  }

  @Test
  public void canAddParticipantToGroup1() {
    final PrivxCreatePrivacyGroup privxCreatePrivacyGroup =
            alice.execute(privacyTransactions.createOnChainPrivacyGroup(alice, alice, bob));

    assertThat(privxCreatePrivacyGroup).isNotNull();

    final String privacyGroupId = privxCreatePrivacyGroup.getPrivacyGroupId();
    final PrivacyGroup expectedGroup =
            new PrivacyGroup(
                    privacyGroupId,
                    PrivacyGroup.Type.PANTHEON,
                    "",
                    "",
                    Base64String.wrapList(alice.getEnclaveKey(), bob.getEnclaveKey()));

    alice.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));
    bob.verify(privateTransactionVerifier.validOnChainPrivacyGroupExists(expectedGroup));
    final EventEmitter eventEmitter =
            alice.execute(
                    privateContractTransactions.createSmartContractWithPrivacyGroupId(
                            EventEmitter.class,
                            alice.getTransactionSigningKey(),
                            POW_CHAIN_ID,
                            alice.getEnclaveKey(),
                            privacyGroupId));
    privateContractVerifier
            .validPrivateContractDeployed(
                    eventEmitter.getContractAddress(), alice.getAddress().toString())
            .verify(eventEmitter);

    final String transactionHash =
            bob.execute(
                    privacyTransactions.addToPrivacyGroup(
                            privacyGroupId, bob, charlie));

    final String callHash = alice.execute(
            privateContractTransactions.callOnChainPermissioningSmartContract(
                    eventEmitter.getContractAddress(),
                    eventEmitter.value().encodeFunctionCall(),
                    alice.getTransactionSigningKey(),
                    POW_CHAIN_ID,
                    alice.getEnclaveKey(),
                    privacyGroupId));

    final PrivacyGroup expectedGroupAfterCharlieIsAdded =
            new PrivacyGroup(
                    privacyGroupId,
                    PrivacyGroup.Type.PANTHEON,
                    "",
                    "",
                    Base64String.wrapList(
                            alice.getEnclaveKey(), bob.getEnclaveKey(), charlie.getEnclaveKey()));

    alice.verify(
            privateTransactionVerifier.validOnChainPrivacyGroupExists(
                    expectedGroupAfterCharlieIsAdded));

    bob.verify(
            privateTransactionVerifier.validOnChainPrivacyGroupExists(
                    expectedGroupAfterCharlieIsAdded));

    charlie.verify(
            privateTransactionVerifier.validOnChainPrivacyGroupExists(
                    expectedGroupAfterCharlieIsAdded));

    final Optional<TransactionReceipt> aliceAddReceipt = alice.execute(ethTransactions.getTransactionReceipt(transactionHash));
    assertThat(aliceAddReceipt.get().getStatus()).isEqualTo("0x1"); // this means the PMT for the "add" succeeded which is what we expect

    final Optional<TransactionReceipt> alicePublicReceipt = alice.execute(ethTransactions.getTransactionReceipt(callHash));
    if (alicePublicReceipt.isPresent()) {
      assertThat(alicePublicReceipt.get().getBlockHash()).isEqualTo(aliceAddReceipt.get().getBlockHash()); // ensure that "add" and "call" are in the same block
      assertThat(alicePublicReceipt.get().getStatus()).isEqualTo("0x1"); // this means the PMT for the "call" succeeded which is what we expect because it is in the same block as the "add" and there is no way to tell that this will happen before the block is mined
    }


    final PrivateTransactionReceipt aliceReceipt =
            alice.execute(privacyTransactions.getPrivateTransactionReceipt(callHash));
    assertThat(aliceReceipt.getStatus()).isEqualTo("0x0"); // this means the "call" failed which is what we expect because the group was locked!
    final PrivateTransactionReceipt bobReceipt =
            alice.execute(privacyTransactions.getPrivateTransactionReceipt(callHash));
    assertThat(bobReceipt.getStatus()).isEqualTo("0x0"); // this means the "call" failed which is what we expect because the group was locked!

    // Charlie will not be able to generate a private transaction receipt because he never received the payload

//    final PrivateTransactionReceipt charlieReceipt =
//            charlie.execute(privacyTransactions.getPrivateTransactionReceipt(callHash));
//    System.out.println("\n\n\nCHARLIE PRIVATE RECEIPT: \n" + charlieReceipt.getStatus());
//    charlie.verify(
//            privateTransactionVerifier.validPrivateTransactionReceipt(
//                    callHash, aliceReceipt));


    final String callHash2 = charlie.execute(
            privateContractTransactions.callOnChainPermissioningSmartContract(
                    eventEmitter.getContractAddress(),
                    eventEmitter.store(BigInteger.valueOf(1337)).encodeFunctionCall(),
                    charlie.getTransactionSigningKey(),
                    POW_CHAIN_ID,
                    charlie.getEnclaveKey(),
                    privacyGroupId));

    final PrivateTransactionReceipt expectedReceipt =
            new PrivateTransactionReceipt(
                    null,
                    charlie.getAddress().toHexString(),
                    eventEmitter.getContractAddress(),
                    "0x",
                    Collections.singletonList(new Log(false, "0x0", "0x0", callHash2, null, null, eventEmitter.getContractAddress(), "0x000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b7320000000000000000000000000000000000000000000000000000000000000539", null, Collections.singletonList("0xc9db20adedc6cf2b5d25252b101ab03e124902a73fcb12b753f3d1aaa2d8f9f5"))),
                    null,
                    null,
                    charlie.getEnclaveKey(),
                    null,
                    privxCreatePrivacyGroup.getPrivacyGroupId(),
                    "0x1",
                    null);

    alice.verify(privateTransactionVerifier.validPrivateTransactionReceipt(callHash2, expectedReceipt));
  }

}
