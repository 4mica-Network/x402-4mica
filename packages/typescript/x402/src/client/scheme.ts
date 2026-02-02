import { SchemeNetworkClient, PaymentRequirements, PaymentPayload } from '@x402/core/types'
import {
  Client,
  ConfigBuilder,
  EvmSigner,
  PaymentRequirementsV1,
  X402Flow,
  X402PaymentRequired,
} from 'sdk-4mica'

export class FourMicaEvmScheme implements SchemeNetworkClient {
  readonly scheme = '4mica-credit'

  private readonly x402Flow: X402Flow

  private constructor(
    private readonly signer: EvmSigner,
    client: Client
  ) {
    this.x402Flow = X402Flow.fromClient(client)
  }

  static async create(signer: EvmSigner, client?: Client): Promise<FourMicaEvmScheme> {
    if (client) return new FourMicaEvmScheme(signer, client)

    const cfg = new ConfigBuilder().signer(signer).build()
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
