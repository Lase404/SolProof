import chalk from 'chalk';
import fetch from 'node-fetch';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Analyzes the update history of a Solana program using Helius RPC.
 *
 * @param {string} address - Program address.
 * @returns {Promise<Array>} - List of update events.
 */
export async function analyzeUpdateHistory(address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const response = await fetch(`https://api.helius.xyz/v0/addresses/${address}/transactions?api-key=${apiKey}&limit=10`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const txs = await response.json();
    const updates = txs
      .filter(tx => tx.type === 'PROGRAM_UPGRADE')
      .map(tx => ({
        timestamp: tx.timestamp,
        changes: ['Program binary updated'],
      }));

    return updates;
  } catch (err) {
    console.warn(chalk.yellow(`Update history analysis failed for ${address}: ${err.message}`));
    return [];
  }
}