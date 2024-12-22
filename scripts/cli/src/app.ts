import { buildApplication, buildRouteMap } from '@stricli/core'
import { buildInstallCommand, buildUninstallCommand } from '@stricli/auto-complete'
import { subdirCommand } from './commands/subdir/command.js'
import { nestedRoutes } from './commands/nested/commands.js'
import { readFileSync } from 'node:fs'

const packageJsonPath = new URL('../package.json', import.meta.url).pathname

const { name, description, version } = JSON.parse(readFileSync(packageJsonPath, 'utf-8'))

const routes = buildRouteMap({
  routes: {
    subdir: subdirCommand,
    nested: nestedRoutes,
    install: buildInstallCommand('cli', { bash: '__cli_bash_complete' }),
    uninstall: buildUninstallCommand('cli', { bash: true }),
  },
  docs: {
    brief: description,
    hideRoute: {
      install: true,
      uninstall: true,
    },
  },
})

export const app = buildApplication(routes, {
  name,
  versionInfo: {
    currentVersion: version,
  },
})
