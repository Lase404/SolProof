import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Analyzes authority holders for a Solana program.
 *
 * @param {Array<string>} authorityHolders - List of authority addresses.
 * @param {string} address - Program address.
 * @returns {Promise<Array>} - Authority insights.
 */
export async function analyzeAuthorityHolders(authorityHolders, address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
    const insights = await Promise.all(
      authorityHolders.map(async auth => {
        const accountInfo = await connection.getAccountInfo(new PublicKey(auth));
        const balance = accountInfo ? accountInfo.lamports / 1e9 : 0;
        const txs = await connection.getSignaturesForAddress(new PublicKey(auth), { limit: 1 });
        const walletAgeDays = txs.length ? Math.floor((Date.now() / 1000 - txs[0].blockTime) / 86400) : 0;

        return {
          authority: auth,
          totalSOLWithdrawn: balance,
          walletAgeDays,
          tokenMintCount: 0, // Simplified; real analysis would fetch token accounts
        };
      })
    );

    return insights;
  } catch (err) {
    console.warn(chalk.yellow(`Authority analysis failed for ${address}: ${err.message}`));
    return [];
  }
}