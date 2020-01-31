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
package org.hyperledger.besu.ethereum.mainnet.precompiles.privacy;

import static org.hyperledger.besu.crypto.Hash.keccak256;
import static org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver.EMPTY_ROOT_HASH;

import org.hyperledger.besu.enclave.Enclave;
import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.EnclaveIOException;
import org.hyperledger.besu.enclave.EnclaveServerException;
import org.hyperledger.besu.enclave.types.ReceiveResponse;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.DefaultEvmAccount;
import org.hyperledger.besu.ethereum.core.Gas;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.MutableAccount;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.PrivacyParameters;
import org.hyperledger.besu.ethereum.core.ProcessableBlockHeader;
import org.hyperledger.besu.ethereum.core.WorldUpdater;
import org.hyperledger.besu.ethereum.debug.TraceOptions;
import org.hyperledger.besu.ethereum.mainnet.AbstractPrecompiledContract;
import org.hyperledger.besu.ethereum.privacy.PrivateStateRootResolver;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionProcessor;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionReceipt;
import org.hyperledger.besu.ethereum.privacy.PrivateTransactionWithMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivacyGroupHeadBlockMap;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateBlockMetadata;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateStateStorage;
import org.hyperledger.besu.ethereum.privacy.storage.PrivateTransactionMetadata;
import org.hyperledger.besu.ethereum.rlp.BytesValueRLPInput;
import org.hyperledger.besu.ethereum.rlp.RLP;
import org.hyperledger.besu.ethereum.vm.DebugOperationTracer;
import org.hyperledger.besu.ethereum.vm.GasCalculator;
import org.hyperledger.besu.ethereum.vm.MessageFrame;
import org.hyperledger.besu.ethereum.worldstate.WorldStateArchive;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt256;

public class OnChainPrivacyPrecompiledContract extends AbstractPrecompiledContract {
  private static final Bytes PROXY_PRECOMPILED_CODE =
      Bytes.fromHexString(
          "0x608060405234801561001057600080fd5b50600436106100885760003560e01c806378b903371161005b57806378b90337146101ee578063a69df4b514610210578063f744b0891461021a578063f83d08ba146102f457610088565b80630b0235be1461008d5780633659cfe6146101105780635c60da1b1461015457806361544c911461019e575b600080fd5b6100b9600480360360208110156100a357600080fd5b81019080803590602001909291905050506102fe565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156100fc5780820151818401526020810190506100e1565b505050509050019250505060405180910390f35b6101526004803603602081101561012657600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610454565b005b61015c6104ba565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b6101d4600480360360408110156101b457600080fd5b8101908080359060200190929190803590602001909291905050506104df565b604051808215151515815260200191505060405180910390f35b6101f66105a5565b604051808215151515815260200191505060405180910390f35b610218610653565b005b6102da6004803603604081101561023057600080fd5b81019080803590602001909291908035906020019064010000000081111561025757600080fd5b82018360208201111561026957600080fd5b8035906020019184602083028401116401000000008311171561028b57600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600081840152601f19601f8201169050808301925050505050505091929192905050506106dc565b604051808215151515815260200191505060405180910390f35b6102fc6107e3565b005b606060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff16630b0235be846040518263ffffffff1660e01b81526004018082815260200191505060006040518083038186803b15801561037757600080fd5b505afa15801561038b573d6000803e3d6000fd5b505050506040513d6000823e3d601f19601f8201168201806040525060208110156103b557600080fd5b81019080805160405193929190846401000000008211156103d557600080fd5b838201915060208201858111156103eb57600080fd5b825186602082028301116401000000008211171561040857600080fd5b8083526020830192505050908051906020019060200280838360005b8381101561043f578082015181840152602081019050610424565b50505050905001604052505050915050919050565b8073ffffffffffffffffffffffffffffffffffffffff166000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614156104ae57600080fd5b6104b78161086c565b50565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff166361544c9185856040518363ffffffff1660e01b81526004018083815260200182815260200192505050602060405180830381600087803b15801561056157600080fd5b505af1158015610575573d6000803e3d6000fd5b505050506040513d602081101561058b57600080fd5b810190808051906020019092919050505091505092915050565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff166378b903376040518163ffffffff1660e01b815260040160206040518083038186803b15801561061257600080fd5b505afa158015610626573d6000803e3d6000fd5b505050506040513d602081101561063c57600080fd5b810190808051906020019092919050505091505090565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff1663a69df4b56040518163ffffffff1660e01b8152600401600060405180830381600087803b1580156106c157600080fd5b505af11580156106d5573d6000803e3d6000fd5b5050505050565b6000806000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff1663f744b08985856040518363ffffffff1660e01b81526004018083815260200180602001828103825283818151815260200191508051906020019060200280838360005b8381101561077957808201518184015260208101905061075e565b505050509050019350505050602060405180830381600087803b15801561079f57600080fd5b505af11580156107b3573d6000803e3d6000fd5b505050506040513d60208110156107c957600080fd5b810190808051906020019092919050505091505092915050565b60008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508073ffffffffffffffffffffffffffffffffffffffff1663f83d08ba6040518163ffffffff1660e01b8152600401600060405180830381600087803b15801561085157600080fd5b505af1158015610865573d6000803e3d6000fd5b5050505050565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055505056fea265627a7a723158205a6e759618cd7c7dbc4db9b59d81b71bbd3014d8062d366d9d5e920a0c9b6cc164736f6c634300050c0032");

  private static final Bytes SIMPLE_GROUP_MANAGEMENT_CODE =
      Bytes.fromHexString(
          "0x608060405234801561001057600080fd5b50600436106100625760003560e01c80630b0235be1461006757806361544c91146100ea57806378b903371461013a578063a69df4b51461015c578063f744b08914610166578063f83d08ba14610240575b600080fd5b6100936004803603602081101561007d57600080fd5b810190808035906020019092919050505061024a565b6040518080602001828103825283818151815260200191508051906020019060200280838360005b838110156100d65780820151818401526020810190506100bb565b505050509050019250505060405180910390f35b6101206004803603604081101561010057600080fd5b8101908080359060200190929190803590602001909291905050506102b6565b604051808215151515815260200191505060405180910390f35b6101426102db565b604051808215151515815260200191505060405180910390f35b6101646102f1565b005b6102266004803603604081101561017c57600080fd5b8101908080359060200190929190803590602001906401000000008111156101a357600080fd5b8201836020820111156101b557600080fd5b803590602001918460208302840111640100000000831117156101d757600080fd5b919080806020026020016040519081016040528093929190818152602001838360200280828437600081840152601f19601f82011690508083019250505050505050919291929050505061030d565b604051808215151515815260200191505060405180910390f35b610248610385565b005b6060610255826103a1565b61025e57600080fd5b60018054806020026020016040519081016040528092919081815260200182805480156102aa57602002820191906000526020600020905b815481526020019060010190808311610296575b50505050509050919050565b60006102c1836103a1565b6102ca57600080fd5b6102d3826103c1565b905092915050565b60008060009054906101000a900460ff16905090565b60016000806101000a81548160ff021916908315150217905550565b60008060009054906101000a900460ff161561032857600080fd5b600060018054905014156103415761033f836104a0565b505b61034a836103a1565b61035357600080fd5b600061035f8484610512565b905060016000806101000a81548160ff0219169083151502179055508091505092915050565b60008060006101000a81548160ff021916908315150217905550565b600080600260008481526020019081526020016000205414159050919050565b600080600260008481526020019081526020016000205490506000811180156103ef57506001805490508111155b1561049557600180549050811461045a5760006001808080549050038154811061041557fe5b906000526020600020015490508060018084038154811061043257fe5b9060005260206000200181905550816002600083815260200190815260200160002081905550505b6001808181805490500391508161047191906107f4565b5060006002600085815260200190815260200160002081905550600191505061049b565b60009150505b919050565b60008060026000848152602001908152602001600020541415610508576001829080600181540180825580915050906001820390600052602060002001600090919290919091505560026000848152602001908152602001600020819055506001905061050d565b600090505b919050565b6000806001905060008090505b83518110156107e95783818151811061053457fe5b60200260200101518514156105c8577fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf213600085838151811061057257fe5b60200260200101516040518083151515158152602001828152602001806020018281038252602f815260200180610867602f9139604001935050505060405180910390a18180156105c1575060005b91506107dc565b6105e48482815181106105d757fe5b60200260200101516103a1565b1561068b577fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf213600085838151811061061857fe5b60200260200101516040518083151515158152602001828152602001806020018281038252601b8152602001807f4163636f756e7420697320616c72656164792061204d656d6265720000000000815250602001935050505060405180910390a1818015610684575060005b91506107db565b60006106a985838151811061069c57fe5b60200260200101516104a0565b90506060816106ed576040518060400160405280601b81526020017f4163636f756e7420697320616c72656164792061204d656d6265720000000000815250610707565b604051806060016040528060218152602001610846602191395b90507fcc7365305ae5f16c463d1383713d699f43c5548bbda5537ee61373ceb9aaf2138287858151811061073757fe5b602002602001015183604051808415151515815260200183815260200180602001828103825283818151815260200191508051906020019080838360005b83811015610790578082015181840152602081019050610775565b50505050905090810190601f1680156107bd5780820380516001836020036101000a031916815260200191505b5094505050505060405180910390a18380156107d65750815b935050505b5b808060010191505061051f565b508091505092915050565b81548183558181111561081b5781836000526020600020918201910161081a9190610820565b5b505050565b61084291905b8082111561083e576000816000905550600101610826565b5090565b9056fe4d656d626572206163636f756e74206164646564207375636365737366756c6c79416464696e67206f776e206163636f756e742061732061204d656d626572206973206e6f74207065726d6974746564a265627a7a723158205805939beeb96350566f55a26cd7b9f9750059c31f257673ceb6aa932b9ea79a64736f6c634300050c0032");

  private final Enclave enclave;
  private final WorldStateArchive privateWorldStateArchive;
  private final PrivateStateStorage privateStateStorage;
  private final PrivateStateRootResolver privateStateRootResolver;
  private PrivateTransactionProcessor privateTransactionProcessor;

  private static final Logger LOG = LogManager.getLogger();

  public OnChainPrivacyPrecompiledContract(
      final GasCalculator gasCalculator, final PrivacyParameters privacyParameters) {
    this(
        gasCalculator,
        privacyParameters.getEnclave(),
        privacyParameters.getPrivateWorldStateArchive(),
        privacyParameters.getPrivateStateStorage());
  }

  OnChainPrivacyPrecompiledContract(
      final GasCalculator gasCalculator,
      final Enclave enclave,
      final WorldStateArchive worldStateArchive,
      final PrivateStateStorage privateStateStorage) {
    super("OnChainPrivacy", gasCalculator);
    this.enclave = enclave;
    this.privateWorldStateArchive = worldStateArchive;
    this.privateStateStorage = privateStateStorage;
    this.privateStateRootResolver = new PrivateStateRootResolver(privateStateStorage);
  }

  public void setPrivateTransactionProcessor(
      final PrivateTransactionProcessor privateTransactionProcessor) {
    this.privateTransactionProcessor = privateTransactionProcessor;
  }

  @Override
  public Gas gasRequirement(final Bytes input) {
    return Gas.of(0L);
  }

  @Override
  public Bytes compute(final Bytes input, final MessageFrame messageFrame) {
    final ProcessableBlockHeader currentBlockHeader = messageFrame.getBlockHeader();
    if (!BlockHeader.class.isAssignableFrom(currentBlockHeader.getClass())) {
      if (!messageFrame.isPersistingState()) {
        // We get in here from block mining.
        return Bytes.EMPTY;
      } else {
        throw new IllegalArgumentException(
            "The MessageFrame contains an illegal block header type. Cannot persist private block metadata without current block hash.");
      }
    }
    final Hash currentBlockHash = ((BlockHeader) currentBlockHeader).getHash();

    final String key;
    final String addKey;
    if (input.size() == 32) {
      key = input.toBase64String();
      addKey = null;
    } else if (input.size() == 64) {
      key = input.slice(0, 32).toBase64String();
      addKey = input.slice(32, 32).toBase64String();
    } else {
      throw new RuntimeException();
    }

    final ReceiveResponse receiveResponse;
    try {
      receiveResponse = enclave.receive(key);
    } catch (final EnclaveClientException e) {
      LOG.debug("Can not fetch private transaction payload with key {}", key, e);
      return Bytes.EMPTY;
    } catch (final EnclaveServerException e) {
      LOG.error("Enclave is responding but errored perhaps it has a misconfiguration?", e);
      throw e;
    } catch (final EnclaveIOException e) {
      LOG.error("Can not communicate with enclave is it up?", e);
      throw e;
    }

    final BytesValueRLPInput bytesValueRLPInput =
        new BytesValueRLPInput(
            Bytes.wrap(Base64.getDecoder().decode(receiveResponse.getPayload())), false);
    final PrivateTransaction privateTransaction = PrivateTransaction.readFrom(bytesValueRLPInput);
    final WorldUpdater publicWorldState = messageFrame.getWorldState();

    // TODO sort out the exception being thrown here
    final Bytes32 privacyGroupId =
        Bytes32.wrap(privateTransaction.getPrivacyGroupId().orElseThrow(RuntimeException::new));

    LOG.trace(
        "Processing private transaction {} in privacy group {}",
        privateTransaction.getHash(),
        privacyGroupId);

    final PrivacyGroupHeadBlockMap privacyGroupHeadBlockMap =
        privateStateStorage.getPrivacyGroupHeadBlockMap(currentBlockHash).orElseThrow();

    final Blockchain currentBlockchain = messageFrame.getBlockchain();

    final Hash lastRootHash =
        privateStateRootResolver.resolveLastStateRoot(privacyGroupId, currentBlockHash);

    final MutableWorldState disposablePrivateState =
        privateWorldStateArchive.getMutable(lastRootHash).get();

    final WorldUpdater privateWorldStateUpdater = disposablePrivateState.updater();

    if (lastRootHash.equals(EMPTY_ROOT_HASH)) {
      // inject management
      final DefaultEvmAccount managementPrecompile =
          privateWorldStateUpdater.createAccount(Address.DEFAULT_PRIVACY_MANAGEMENT);
      final MutableAccount mutableManagementPrecompiled = managementPrecompile.getMutable();
      // this is the code for the simple management contract
      mutableManagementPrecompiled.setCode(SIMPLE_GROUP_MANAGEMENT_CODE);

      // inject proxy
      final DefaultEvmAccount proxyPrecompile =
          privateWorldStateUpdater.createAccount(Address.PRIVACY_PROXY);
      final MutableAccount mutableProxyPrecompiled = proxyPrecompile.getMutable();
      // this is the code for the proxy contract
      mutableProxyPrecompiled.setCode(PROXY_PRECOMPILED_CODE);
      // manually set the management contract address so the proxy can trust it
      mutableProxyPrecompiled.setStorageValue(
          UInt256.ZERO, UInt256.fromBytes(Bytes32.leftPad(Address.DEFAULT_PRIVACY_MANAGEMENT)));
    }

    if (addKey != null && privacyGroupHeadBlockMap.get(privacyGroupId) == null) {
      final ReceiveResponse addReceiveResponse;
      try {
        addReceiveResponse = enclave.receive(addKey);
        final List<PrivateTransactionWithMetadata> privateTransactionWithMetadataList =
            deserializeAddToGroupPayload(
                Bytes.wrap(Base64.getDecoder().decode(addReceiveResponse.getPayload())));
        privateTransactionWithMetadataList.forEach(
            pt -> {
              final PrivateTransactionProcessor.Result result =
                  privateTransactionProcessor.processTransaction(
                      currentBlockchain,
                      publicWorldState,
                      privateWorldStateUpdater,
                      currentBlockHeader,
                      pt.getPrivateTransaction(),
                      messageFrame.getMiningBeneficiary(),
                      new DebugOperationTracer(TraceOptions.DEFAULT),
                      messageFrame.getBlockHashLookup(),
                      privacyGroupId);
              if (result.isInvalid()
                  || !result.isSuccessful()
                  || !disposablePrivateState
                      .rootHash()
                      .equals(pt.getPrivateTransactionMetadata().getStateRoot())) {
                LOG.error(
                    "Failed to rehydrate private transaction {}: {} - Expecting root hash {}, and got {}",
                    privateTransaction.getHash(),
                    result.getValidationResult().getErrorMessage(),
                    disposablePrivateState.rootHash().toHexString(),
                    pt.getPrivateTransactionMetadata().getStateRoot());
              }
              privateWorldStateUpdater.commit();
              disposablePrivateState.persist();
            });
      } catch (final EnclaveClientException e) {
        LOG.debug("Can not fetch private transaction payload with key {}", key, e);
        return Bytes.EMPTY;
      } catch (final EnclaveServerException e) {
        LOG.error("Enclave is responding but errored perhaps it has a misconfiguration?", e);
        throw e;
      } catch (final EnclaveIOException e) {
        LOG.error("Can not communicate with enclave is it up?", e);
        throw e;
      }
    }

    final PrivateTransactionProcessor.Result result =
        privateTransactionProcessor.processTransaction(
            currentBlockchain,
            publicWorldState,
            privateWorldStateUpdater,
            currentBlockHeader,
            privateTransaction,
            messageFrame.getMiningBeneficiary(),
            new DebugOperationTracer(TraceOptions.DEFAULT),
            messageFrame.getBlockHashLookup(),
            privacyGroupId);

    if (result.isInvalid() || !result.isSuccessful()) {
      LOG.error(
          "Failed to process private transaction {}: {}",
          privateTransaction.getHash(),
          result.getValidationResult().getErrorMessage());
      return Bytes.EMPTY;
    }

    if (messageFrame.isPersistingState()) {
      LOG.trace(
          "Persisting private state {} for privacyGroup {}",
          disposablePrivateState.rootHash(),
          privacyGroupId);
      privateWorldStateUpdater.commit();
      disposablePrivateState.persist();

      final PrivateStateStorage.Updater privateStateUpdater = privateStateStorage.updater();

      updatePrivateBlockMetadata(
          messageFrame.getTransactionHash(),
          currentBlockHash,
          privacyGroupId,
          disposablePrivateState.rootHash(),
          privateStateUpdater);

      final Bytes32 txHash = keccak256(RLP.encode(privateTransaction::writeTo));

      final int txStatus =
          result.getStatus() == PrivateTransactionProcessor.Result.Status.SUCCESSFUL ? 1 : 0;

      final PrivateTransactionReceipt privateTransactionReceipt =
          new PrivateTransactionReceipt(
              txStatus, result.getLogs(), result.getOutput(), result.getRevertReason());

      privateStateUpdater.putTransactionReceipt(
          currentBlockHash, txHash, privateTransactionReceipt);

      // TODO: this map could be passed through from @PrivacyBlockProcessor and saved once at the
      // end of block processing
      if (!privacyGroupHeadBlockMap.contains(Bytes32.wrap(privacyGroupId), currentBlockHash)) {
        privacyGroupHeadBlockMap.put(Bytes32.wrap(privacyGroupId), currentBlockHash);
        privateStateUpdater.putPrivacyGroupHeadBlockMap(
            currentBlockHash, new PrivacyGroupHeadBlockMap(privacyGroupHeadBlockMap));
      }
      privateStateUpdater.commit();
    }

    return result.getOutput();
  }

  private void updatePrivateBlockMetadata(
      final Hash markerTransactionHash,
      final Hash currentBlockHash,
      final Bytes32 privacyGroupId,
      final Hash rootHash,
      final PrivateStateStorage.Updater privateStateUpdater) {
    final PrivateBlockMetadata privateBlockMetadata =
        privateStateStorage
            .getPrivateBlockMetadata(currentBlockHash, Bytes32.wrap(privacyGroupId))
            .orElseGet(PrivateBlockMetadata::empty);
    privateBlockMetadata.addPrivateTransactionMetadata(
        new PrivateTransactionMetadata(markerTransactionHash, rootHash));
    privateStateUpdater.putPrivateBlockMetadata(
        Bytes32.wrap(currentBlockHash), Bytes32.wrap(privacyGroupId), privateBlockMetadata);
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
