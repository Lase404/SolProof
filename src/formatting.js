import chalk from 'chalk';

export const success = msg => chalk.green(msg || 'Success');
export const error = msg => chalk.red(msg || 'Error');
export const warning = msg => chalk.yellow(msg || 'Warning');
export const sectionHeader = title => `\n════ ${chalk.bold.underline.cyan(title)} ════\n`;
export const emoji = {
  shield: '🛡️',
  alert: '🚨',
  warning: '⚠️',
  search: '🔍',
  ai: '🤖',
  link: '🔗'
};