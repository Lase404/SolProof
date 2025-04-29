
export function formatAddress(address) {
    if (!address) return 'unknown';
    return `${address.slice(0, 4)}...${address.slice(-4)}`;
  }
  
  
  export function formatAmount(amount, unit) {
    if (typeof amount !== 'number') return 'unknown';
    return `${amount.toFixed(4)} ${unit}`;
  }