import { HttpService } from 'synapse:srl/compute'
import { MachineIdentityInternal } from '@cohesible/auth'
import { getClaims } from './jwt'
import { fetch, HttpError } from 'synapse:http'


const identity = new MachineIdentityInternal()

const service = new HttpService({ auth: 'none' })

const exchangeRoute = service.addRoute('POST /token/exchange', async (req, body: { type: 'github'; token: string }) => {
    if (!body) {
        throw new HttpError(`Missing request body`, { status: 400 })
    }

    if (typeof body !== 'object' || body.type !== 'github') {
        throw new HttpError(`Only GitHub tokens can be exchanged`, { status: 400 })
    }

    const token = body.token
    if (!token) {
        throw new HttpError(`No token provided`, { status: 400 })
    }

    // TODO: we have control over `aud`, change and check it
    const claims = await getClaims(token)
    if (Date.now() / 1000 > claims.exp) {
        throw new HttpError(`Token is expired`, { status: 400 })
    }

    if (claims.iss !== 'https://token.actions.githubusercontent.com') {
        throw new HttpError(`Invalid issuer`, { status: 400 })
    }

    if (claims.repository !== 'Cohesible/synapse') {
        throw new HttpError(`Invalid repository`, { status: 400 })
    }

    return identity.getCredentials()
})

export interface Credentials {
    access_token: string
    expiresAt: number
}

export function exchangeToken(token: string): Promise<Credentials> {
    return fetch(exchangeRoute, { type: 'github', token })
}