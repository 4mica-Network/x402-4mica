import '@x402/core/server'

declare module '@x402/core/server' {
  interface x402HTTPResourceServer {
    get routes(): import('@x402/core/server').RoutesConfig
    get server(): import('@x402/core/server').x402ResourceServer
  }

  interface x402ResourceServer {
    hasExtension(name: string): boolean
  }
}
