import * as core from '@actions/core'
import { exchangeToken } from './backend'

export async function main() {
    const token = await core.getIDToken()
    const creds = await exchangeToken(token)
    const encoded = Buffer.from(creds.access_token).toString('base64')

    core.setSecret(creds.access_token)
    core.setSecret(encoded)

    core.exportVariable('COHESIBLE_AUTH', JSON.stringify(creds))
    core.exportVariable('COHESIBLE_AUTH_TOKEN', encoded)
}

