import { Connection, PublicKey } from '@solana/web3.js';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

export async function fetchProgramBinary(address) {
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  try {
    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
    const programId = new PublicKey(address);
    const accountInfo = await connection.getAccountInfo(programId);
    
    if (!accountInfo) throw new Error(`Program account ${address} not found`);
    if (!accountInfo.executable) throw new Error(`Account ${address} is not executable`);

    return accountInfo.data;
  } catch (err) {
    console.warn(chalk.yellow(`Failed to fetch binary for ${address}: ${err.message}`));
    throw err;
  }
}