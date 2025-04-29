import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

/**
 * Performs a quick check on a Solana program’s status.
 *
 * @param {string} address - Program address.
 * @returns {Promise<Object>} - Program status details.
 */
export async function quickCheck(address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
    const programId = new PublicKey(address);
    const accountInfo = await connection.getAccountInfo(programId);
    const txs = await connection.getSignaturesForAddress(programId, { limit: 1 });

    return {
      isActive: !!accountInfo,
      lastTransaction: txs.length ? txs[0].blockTime : null,
      isUpgradeable: accountInfo?.owner.toBase58() === 'BPFLoaderUpgradeableProgram1111111111111111111111111111111111',
      upgradeAuthority: accountInfo?.data?.slice(4, 36)?.toString('base58') || null,
      basicSafetyScore: accountInfo && txs.length ? 60 : 40,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Quick check failed for ${address}: ${err.message}`));
    return {
      isActive: false,
      lastTransaction: null,
      isUpgradeable: false,
      upgradeAuthority: null,
      basicSafetyScore: 40,
    };
  }
}