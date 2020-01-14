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

import org.hyperledger.besu.ethereum.core.Log;
import org.hyperledger.besu.ethereum.rlp.RLPInput;
import org.hyperledger.besu.ethereum.rlp.RLPOutput;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.google.common.base.MoreObjects;
import org.apache.tuweni.bytes.Bytes;

/**
 * A transaction receipt for a private transaction, containing information pertaining a transaction
 * execution.
 */
public class PrivateTransactionReceipt {

  @SuppressWarnings("unchecked")
  public static final PrivateTransactionReceipt EMPTY =
      new PrivateTransactionReceipt(
          0, Collections.EMPTY_LIST, Bytes.EMPTY, Optional.of(Bytes.EMPTY));

  private final int status;
  private final List<Log> logs;
  private final Bytes output;
  private final Optional<Bytes> revertReason;

  /**
   * Creates an instance of a state root-encoded transaction receipt.
   *
   * @param status the state root for the world state after the transaction has been processed
   * @param logs the total amount of gas consumed in the block after this transaction
   * @param output output from the transaction
   * @param revertReason the revert reason for a failed transaction (if applicable)
   */
  public PrivateTransactionReceipt(
      final int status,
      final List<Log> logs,
      final Bytes output,
      final Optional<Bytes> revertReason) {
    this.status = status;
    this.logs = logs;
    this.output = output;
    this.revertReason = revertReason;
  }

  /**
   * Write an RLP representation.
   *
   * @param out The RLP output to write to
   */
  public void writeTo(final RLPOutput out) {
    out.startList();

    out.writeLongScalar(status);
    out.writeList(logs, Log::writeTo);
    out.writeBytes(output);
    if (revertReason.isPresent()) {
      out.writeBytes(revertReason.get());
    }
    out.endList();
  }

  /**
   * Creates a transaction receipt for the given RLP
   *
   * @param input the RLP-encoded transaction receipt
   * @return the transaction receipt
   */
  public static PrivateTransactionReceipt readFrom(final RLPInput input) {
    input.enterList();

    try {
      // Get the first element to check later to determine the
      // correct transaction receipt encoding to use.
      final int status = input.readIntScalar();
      final List<Log> logs = input.readList(Log::readFrom);
      final Bytes output = input.readBytes();
      final Optional<Bytes> revertReason;
      if (input.isEndOfCurrentList()) {
        revertReason = Optional.empty();
      } else {
        revertReason = Optional.of(input.readBytes());
      }
      return new PrivateTransactionReceipt(status, logs, output, revertReason);
    } finally {
      input.leaveList();
    }
  }

  /**
   * Returns the status code for the status-encoded transaction receipt
   *
   * @return the status code if the transaction receipt is status-encoded; otherwise {@code -1}
   */
  public int getStatus() {
    return status;
  }

  /**
   * Returns the logs generated by the transaction.
   *
   * @return the logs generated by the transaction
   */
  public List<Log> getLogs() {
    return logs;
  }

  /**
   * Returns the output generated by the transaction.
   *
   * @return the output generated by the transaction
   */
  public Bytes getOutput() {
    return output;
  }

  /**
   * Returns the revert reason generated by the transaction.
   *
   * @return the revert reason generated by the transaction
   */
  public Optional<Bytes> getRevertReason() {
    return revertReason;
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    }
    if (!(obj instanceof PrivateTransactionReceipt)) {
      return false;
    }
    final PrivateTransactionReceipt other = (PrivateTransactionReceipt) obj;
    return logs.equals(other.getLogs())
            && status == other.status
            && output.equals(other.output)
            && revertReason.isPresent()
        ? revertReason.get().equals(other.revertReason.get())
        : true;
  }

  @Override
  public int hashCode() {
    return Objects.hash(status, logs, output, revertReason);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("status", status)
        .add("logs", logs)
        .add("output", output)
        .add("revertReason", revertReason)
        .toString();
  }
}
