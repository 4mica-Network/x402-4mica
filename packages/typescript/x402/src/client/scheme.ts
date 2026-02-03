import { SchemeNetworkClient, PaymentRequirements, PaymentPayload } from '@x402/core/types'
import {
  Client,
  ConfigBuilder,
  PaymentRequirementsV1,
  X402Flow,
  X402PaymentRequired,
} from '@4mica/sdk'
import { Account } from 'viem/accounts'

export class FourMicaEvmScheme implements SchemeNetworkClient {
  readonly scheme = '4mica-credit'

  private readonly x402Flow: X402Flow

  private constructor(
    private readonly signer: Account,
    client: Client
  ) {
    this.x402Flow = X402Flow.fromClient(client)
  }

  static async create(signer: Account, client?: Client): Promise<FourMicaEvmScheme> {
    if (client) return new FourMicaEvmScheme(signer, client)

    const cfg = new ConfigBuilder().rpcUrl('https://api.4mica.xyz').signer(signer).build()
    return new FourMicaEvmScheme(signer, await Client.new(cfg))
  }

  async createPaymentPayload(
    x402Version: number,
    paymentRequirements: PaymentRequirements
  ): Promise<Pick<PaymentPayload, 'x402Version' | 'payload'>> {
    if (x402Version === 1) {
      const signed = await this.x402Flow.signPayment(
        paymentRequirements as unknown as PaymentRequirementsV1,
        this.signer.address
      )
      return {
        x402Version: 1,
        payload: signed.payload as unknown as Record<string, unknown>,
      }
    } else if (x402Version === 2) {
      const paymentRequired: X402PaymentRequired = {
        x402Version: 2,
        resource: { url: '', description: '', mimeType: '' },
        accepts: [paymentRequirements],
      }
      const signed = await this.x402Flow.signPaymentV2(
        paymentRequired,
        paymentRequirements,
        this.signer.address
      )

      return {
        x402Version: 2,
        payload: signed.payload as unknown as Record<string, unknown>,
      }
    }

    throw new Error(`Unsupported x402Version: ${x402Version}`)
  }
}
