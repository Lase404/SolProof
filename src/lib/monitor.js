
import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import { success, error } from '../formatting.js';

/**
 * Starts real-time monitoring of program transactions.
 * @param {string} address - Program address to monitor.
 * @param {Object} options - Monitoring options.
 * @param {number} options.threshold - Minimum lamport threshold for alerts.
 * @param {string} options.commitment - Commitment level (e.g., 'confirmed').
 * @returns {Promise<void>}
 */
export async function startMonitoring(address, { threshold = 1000000000, commitment = 'confirmed' } = {}) {
  const SUPPORT_EMAIL = 'support@solproof.org';
  let connection;
  let subscriptionId;

  try {
    // Validate address
    try {
      new PublicKey(address);
    } catch (err) {
      throw new Error(`Invalid program address: ${address}`);
    }

    // Initialize connection using QuickNode or Helius RPC
    const rpcUrl = process.env.QUICKNODE_RPC_URL || `https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY}`;
    if (!rpcUrl) {
      throw new Error('No RPC URL configured. Set QUICKNODE_RPC_URL or HELIUS_API_KEY in .env');
    }
    connection = new Connection(rpcUrl, { commitment, wsEndpoint: rpcUrl.replace('https', 'wss') });

    // Define filters for program account changes
    const filters = [
      {
        memcmp: {
          offset: 0,
          bytes: address,
        },
      },
    ];

    // Subscribe to program account changes
    subscriptionId = await connection.onProgramAccountChange(
      new PublicKey(address),
      async (keyedAccountInfo, context) => {
        try {
          const { accountInfo } = keyedAccountInfo;
          const lamports = accountInfo.lamports || 0;
          if (lamports < threshold) return; // Skip transactions below threshold

          // Fetch recent signatures to approximate transaction details
          const signatures = await connection.getSignaturesForAddress(new PublicKey(address), { limit: 1 });
          const signature = signatures[0]?.signature || `slot-${context.slot}`;
          const transaction = await connection.getParsedTransaction(signature, {
            maxSupportedTransactionVersion: 0,
            commitment,
          }).catch(() => null);

          const volumeSOL = lamports / 1e9;
          const accounts = transaction?.transaction.message.accountKeys?.map(key => key.pubkey.toBase58()) || [address];
          const timestamp = transaction?.blockTime ? new Date(transaction.blockTime * 1000).toISOString() : new Date().toISOString();

          // Format alert
          console.log(chalk.yellow('\n⚠️ Transaction Alert'));
          console.log(chalk.cyan('--------------------'));
          console.log(chalk.white(`Signature: ${signature.slice(0, 8)}... (https://solscan.io/tx/${signature})`));
          console.log(chalk.white(`Volume: ${volumeSOL.toFixed(4)} SOL (~$${(volumeSOL * 148.95).toFixed(2)})`));
          console.log(chalk.white(`Accounts Involved:`));
          accounts.slice(0, 3).forEach(acc => console.log(chalk.white(`  - ${acc.slice(0, 8)}... (https://solscan.io/account/${acc})`)));
          console.log(chalk.white(`Timestamp: ${timestamp}`));
          console.log(chalk.cyan('Recommendations:'));
          console.log(chalk.white(`  - Review transaction: https://solscan.io/tx/${signature}`));
          console.log(chalk.white(`  - Run \`trace-interactions ${address}\` to analyze accounts.`));
        } catch (err) {
          console.log(chalk.red(`Error processing transaction: ${err.message}`));
          console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
        }
      },
      commitment,
      filters
    );

    // Log subscription success
    console.log(success(`Monitoring ${address.slice(0, 8)}... for transactions above ${(threshold / 1e9).toFixed(2)} SOL (Subscription ID: ${subscriptionId})`));
    console.log(chalk.gray('Press Ctrl+C to stop.'));

    // Keep process alive for WebSocket
    await new Promise((resolve, reject) => {
      process.on('SIGINT', async () => {
        try {
          if (subscriptionId !== undefined) {
            await connection.removeProgramAccountChangeListener(subscriptionId);
            console.log(success('Monitoring stopped.'));
          }
          resolve();
        } catch (err) {
          reject(new Error(`Failed to unsubscribe: ${err.message}`));
        }
      });
    });
  } catch (err) {
    console.log(error(`Monitoring failed: ${err.message}`));
    console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
    console.log(chalk.red(`Contact ${SUPPORT_EMAIL} for assistance.`));
    throw err;
  } finally {
    if (connection && subscriptionId !== undefined) {
      try {
        await connection.removeProgramAccountChangeListener(subscriptionId);
      } catch (err) {
        console.log(chalk.yellow(`Warning: Failed to clean up subscription: ${err.message}`));
      }
    }
  }
}

