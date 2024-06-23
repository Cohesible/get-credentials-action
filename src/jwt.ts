import * as http from 'synapse:http'
import * as crypto from 'node:crypto'

interface JsonWebKeyExt extends crypto.JsonWebKey {
    kid: string
    use: 'sig'
    alg: string

    // x509
    x5c?: string[]
    x5t?: string
}

async function getGitHubKeys(): Promise<JsonWebKeyExt[]> {
    const resp = await http.fetch('https://token.actions.githubusercontent.com/.well-known/jwks')

    return resp.keys
}

const importedKeys: Record<string, JsonWebKeyExt> = {}
async function importKey(kid: string) {
    if (importedKeys[kid]) {
        return importedKeys[kid]
    }

    const keys = await getGitHubKeys()
    const jwk = keys.find(k => k.kid === kid)
    if (!jwk) {
        throw new Error(`Key not found: ${kid}`)
    }

    return importedKeys[kid] = jwk
}

interface JwtClaims {
    iss?: string
    sub?: string
    aud?: string | string[]
    exp?: number
    nbf?: number
    iat?: number
    jti?: string 
}

interface JwtHeader {
    readonly alg: string
    readonly kid?: string
    readonly crv?: string
    readonly x5t?: string
}

interface JwtComponents {
    readonly header: JwtHeader
    readonly claims: JwtClaims
    readonly sig: Uint8Array
    readonly computedSig: Uint8Array
}

// The signature is _not_ checked
function getComponents(token: string): JwtComponents {
    const [header, body, signature] = token.split('.')
    
    return {
        header: JSON.parse(Buffer.from(header, 'base64url').toString('utf-8')),
        claims: JSON.parse(Buffer.from(body, 'base64url').toString('utf-8')),
        sig: Buffer.from(signature, 'base64url'),
        computedSig: Buffer.from(header + '.' + body),
    }
}

export interface GitHubJwt extends JwtClaims {
    iat: number
    nbf: number
    exp: number
    iss: string
    runner_environment: 'github-hosted' | string
    jti: string
    sub: string // 'repo:Cohesible/synapse:ref:refs/heads/main'
    aud: string // `https://github.com/${repoOwner}` by default
    ref: string //'refs/heads/main'
    sha: string
    repository: string
    repository_owner: string
    repository_owner_id: string
    run_id: string
    run_number: string
    run_attempt: string
    repository_visibility: 'public' | 'private'
    repository_id: string
    actor_id: string
    actor: string
    workflow: string // '.github/workflows/test.yml'
    head_ref: string // only on PRs, '' otherwise
    base_ref: string // only on PRs, '' otherwise
    event_name: string // e.g. `push`
    ref_protected: 'true' | 'false'
    ref_type: 'branch' // not sure what else
    workflow_ref: string // 'Cohesible/synapse/.github/workflows/test.yml@refs/heads/main',
    workflow_sha: string
    job_workflow_ref: string // 'Cohesible/synapse/.github/workflows/test.yml@refs/heads/main',
    job_workflow_sha: string
}

// Caller must check if the token is expired
export async function getClaims(token: string): Promise<GitHubJwt> {
    const components = getComponents(token)
    const kid = components.header.kid
    if (!kid) {
        throw new Error(`JWT header contains no key id`)
    }

    const key = await importKey(kid)
    const isValid = crypto.verify('SHA256', components.computedSig, { key, format: 'jwk' }, components.sig)
    if (!isValid) {
        throw new Error(`Invalid signature`)
    }

    return components.claims as GitHubJwt
}
