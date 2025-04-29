import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Extracts state variables from Solana program accounts.
 *
 * @param {string} address - Program address.
 * @returns {Promise<Array>} - List of program accounts with state data.
 */
export async function extractState(address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
    const programId = new PublicKey(address);
    const accounts = await connection.getProgramAccounts(programId, { commitment: 'confirmed' });

    return accounts.map(account => ({
      account: account.pubkey.toBase58(),
      lamports: account.account.lamports,
      dataLength: account.account.data.length,
      data: account.account.data.toString('hex').slice(0, 20),
    }));
  } catch (err) {
    console.warn(chalk.yellow(`State extraction failed for ${address}: ${err.message}`));
    return [];
  }
}