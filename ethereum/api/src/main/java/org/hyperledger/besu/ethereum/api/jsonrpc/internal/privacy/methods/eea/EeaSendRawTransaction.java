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
package org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.eea;

import org.hyperledger.besu.enclave.EnclaveClientException;
import org.hyperledger.besu.enclave.types.PrivacyGroup;
import org.hyperledger.besu.ethereum.api.jsonrpc.JsonRpcEnclaveErrorConverter;
import org.hyperledger.besu.ethereum.api.jsonrpc.JsonRpcErrorConverter;
import org.hyperledger.besu.ethereum.api.jsonrpc.RpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.JsonRpcRequestContext;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.methods.JsonRpcMethod;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.EnclavePublicKeyProvider;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.PrivacySendTransaction;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.privacy.methods.PrivacySendTransaction.ErrorResponseException;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcErrorResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcResponse;
import org.hyperledger.besu.ethereum.api.jsonrpc.internal.response.JsonRpcSuccessResponse;
import org.hyperledger.besu.ethereum.core.Address;
import org.hyperledger.besu.ethereum.core.Hash;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.eth.transactions.TransactionPool;
import org.hyperledger.besu.ethereum.privacy.OnChainPrivacyController;
import org.hyperledger.besu.ethereum.privacy.PrivacyController;
import org.hyperledger.besu.ethereum.privacy.PrivateTransaction;
import org.hyperledger.besu.ethereum.privacy.SendTransactionResponse;

import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class EeaSendRawTransaction implements JsonRpcMethod {

  private final PrivacySendTransaction privacySendTransaction;
  private final EnclavePublicKeyProvider enclavePublicKeyProvider;
  private final TransactionPool transactionPool;
  private final PrivacyController privacyController;
  private final OnChainPrivacyController onChainPrivacyController;

  public EeaSendRawTransaction(
      final TransactionPool transactionPool,
      final PrivacyController privacyController,
      final OnChainPrivacyController onChainPrivacyController,
      final EnclavePublicKeyProvider enclavePublicKeyProvider) {
    this.transactionPool = transactionPool;
    this.privacyController = privacyController;
    this.onChainPrivacyController = onChainPrivacyController;
    this.privacySendTransaction =
        new PrivacySendTransaction(privacyController, enclavePublicKeyProvider);
    this.enclavePublicKeyProvider = enclavePublicKeyProvider;
  }

  @Override
  public String getName() {
    return RpcMethod.EEA_SEND_RAW_TRANSACTION.getMethodName();
  }

  @Override
  public JsonRpcResponse response(final JsonRpcRequestContext requestContext) {
    final PrivateTransaction privateTransaction;
    try {
      privateTransaction = privacySendTransaction.validateAndDecodeRequest(requestContext);
    } catch (final ErrorResponseException e) {
      return e.getResponse();
    }

    final String addPayloadEnclaveKey;
    if (privacyController.isGroupAdditionTransaction(privateTransaction)) {
      final List<Hash> hashes =
          onChainPrivacyController.buildTransactionList(
              Bytes32.wrap(privateTransaction.getPrivacyGroupId().get()));
      if (hashes.size() > 0) {
        final List<PrivateTransaction> privateTransactions =
            onChainPrivacyController.retrievePrivateTransactions(
                hashes, enclavePublicKeyProvider.getEnclaveKey(requestContext.getUser()));
        final Bytes bytes =
            onChainPrivacyController.serializeAddToGroupPayload(hashes, privateTransactions);
        addPayloadEnclaveKey =
            privacyController.sendAddPayload(
                bytes.toBase64String(),
                enclavePublicKeyProvider.getEnclaveKey(requestContext.getUser()),
                privateTransaction);
      } else {
        addPayloadEnclaveKey = null;
      }
    } else {
      addPayloadEnclaveKey = null;
    }

    final SendTransactionResponse sendTransactionResponse;
    try {
      sendTransactionResponse =
          privacyController.sendTransaction(
              privateTransaction, enclavePublicKeyProvider.getEnclaveKey(requestContext.getUser()));
    } catch (final Exception e) {
      return new JsonRpcErrorResponse(
          requestContext.getRequest().getId(),
          JsonRpcEnclaveErrorConverter.convertEnclaveInvalidReason(e.getMessage()));
    }

    return privacySendTransaction.validateAndExecute(
        requestContext,
        privateTransaction,
        sendTransactionResponse.getPrivacyGroupId(),
        () -> {
          final Transaction privacyMarkerTransaction;
          if (privateTransaction.getPrivacyGroupId().isPresent()) {
            PrivacyGroup privacyGroup = null;
            try {
              privacyGroup =
                  privacyController.retrievePrivacyGroup(
                      privateTransaction.getPrivacyGroupId().get().toBase64String());
            } catch (final EnclaveClientException e) {
              // it is an onchain group
            }
            if (privacyGroup == null
                || !privacyGroup
                    .getMembers()
                    .contains(enclavePublicKeyProvider.getEnclaveKey(requestContext.getUser()))) {
              privacyMarkerTransaction =
                  privacyController.createPrivacyMarkerTransaction(
                      buildCompoundKey(
                          sendTransactionResponse.getEnclaveKey(), addPayloadEnclaveKey),
                      privateTransaction,
                      Address.ONCHAIN_PRIVACY);
            } else {
              privacyMarkerTransaction =
                  privacyController.createPrivacyMarkerTransaction(
                      sendTransactionResponse.getEnclaveKey(), privateTransaction);
            }
          } else {
            privacyMarkerTransaction =
                privacyController.createPrivacyMarkerTransaction(
                    sendTransactionResponse.getEnclaveKey(), privateTransaction);
          }
          return transactionPool
              .addLocalTransaction(privacyMarkerTransaction)
              .either(
                  () ->
                      new JsonRpcSuccessResponse(
                          requestContext.getRequest().getId(),
                          privacyMarkerTransaction.getHash().toString()),
                  errorReason ->
                      new JsonRpcErrorResponse(
                          requestContext.getRequest().getId(),
                          JsonRpcErrorConverter.convertTransactionInvalidReason(errorReason)));
        });
  }

  private String buildCompoundKey(final String enclaveKey, final String addPayloadEnclaveKey) {
    return addPayloadEnclaveKey != null
        ? Bytes.concatenate(
                Bytes.fromBase64String(enclaveKey), Bytes.fromBase64String(addPayloadEnclaveKey))
            .toBase64String()
        : enclaveKey;
  }
}
