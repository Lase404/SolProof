import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Traces user interactions with a Solana program.
 *
 * @param {string} address - Program address.
 * @returns {Promise<Array>} - List of interactions.
 */
export async function traceInteractions(address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
    const txs = await connection.getSignaturesForAddress(new PublicKey(address), { limit: 10 });

    return txs.map(tx => ({
      caller: tx.signature.slice(0, 8) + '...',
      instructionData: tx.memo || 'unknown',
      timestamp: tx.blockTime * 1000,
    }));
  } catch (err) {
    console.warn(chalk.yellow(`Interaction tracing failed for ${address}: ${err.message}`));
    return [];
  }
}