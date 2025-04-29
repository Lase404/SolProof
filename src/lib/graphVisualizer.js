import chalk from 'chalk';

/**
 * Visualizes a Solana program’s call graph in DOT format.
 *
 * @param {Object} callGraph - Call graph data with nodes and edges.
 * @returns {Promise<string>} - DOT format string for Graphviz.
 */
export async function visualizeGraph(callGraph) {
  try {
    if (!callGraph?.nodes || !callGraph?.edges) throw new Error('Invalid call graph data');

    const lines = ['digraph CallGraph {', '  rankdir=LR;', '  node [shape=box];'];

    callGraph.nodes.forEach(node => {
      lines.push(`  "${node}" [label="${node.slice(0, 8)}..."];`);
    });

    callGraph.edges.forEach(edge => {
      lines.push(`  "${edge.from}" -> "${edge.to}" [label="${edge.action} (${edge.count})"];`);
    });

    lines.push('}');
    return lines.join('\n');
  } catch (err) {
    console.warn(chalk.yellow(`Call graph visualization failed: ${err.message}`));
    return 'digraph CallGraph { }';
  }
}