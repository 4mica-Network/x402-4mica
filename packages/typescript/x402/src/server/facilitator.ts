import { FacilitatorConfig, HTTPFacilitatorClient } from '@x402/core/server'
import { Network, PaymentRequirements } from '@x402/core/types'

const DEFAULT_FACILITATOR_URL = 'https://x402.4mica.xyz'

export interface OpenTabRequest {
  userAddress: string
  recipientAddress: string
  network?: Network
  erc20Token?: string
  ttlSeconds?: number
}

export interface OpenTabResponse {
  tabId: string
  userAddress: string
  recipientAddress: string
  assetAddress: string
  startTimestamp: number
  ttlSeconds: number
  nextReqId: string
}

export class OpenTabError extends Error {
  constructor(
    public readonly status: number,
    public readonly response: OpenTabResponse
  ) {
    super(`OpenTab failed with status ${status}`)
    this.name = 'OpenTabError'
  }
}

export class FourMicaFacilitatorClient extends HTTPFacilitatorClient {
  constructor(config?: FacilitatorConfig) {
    super({ ...config, url: config?.url ?? DEFAULT_FACILITATOR_URL })
  }

  async openTab(
    userAddress: string,
    paymentRequirements: PaymentRequirements,
    ttlSeconds?: number
  ): Promise<OpenTabResponse> {
    let headers: Record<string, string> = {
      'Content-Type': 'application/json',
    }

    const authHeaders = await this.createAuthHeaders('tabs')
    headers = { ...headers, ...authHeaders.headers }

    const response = await fetch(`${this.url}/tabs`, {
      method: 'POST',
      headers,
      body: JSON.stringify(
        this.safeJson({
          userAddress,
          recipientAddress: paymentRequirements.payTo,
          network: paymentRequirements.network,
          erc20Token: paymentRequirements.asset,
          ttlSeconds,
        })
      ),
    })

    const data = await response.json()

    if (typeof data === 'object' && data !== null && 'tabId' in data) {
      const openTabResponse = data as OpenTabResponse
      if (!response.ok) {
        throw new OpenTabError(response.status, openTabResponse)
      }
      return openTabResponse
    }

    throw new Error(`Facilitator openTab failed (${response.status}): ${JSON.stringify(data)}`)
  }

  /**
   * Helper to convert objects to JSON-safe format.
   * Handles BigInt and other non-JSON types.
   *
   * @param obj - The object to convert
   * @returns The JSON-safe representation of the object
   */
  private safeJson<T>(obj: T): T {
    return JSON.parse(
      JSON.stringify(obj, (_, value) => (typeof value === 'bigint' ? value.toString() : value))
    )
  }
}
