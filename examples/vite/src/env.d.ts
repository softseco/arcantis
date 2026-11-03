/// <reference types="vite/client" />

// Optional settings, read at build time from the environment or a .env file.
interface ImportMetaEnv {
  /** RPC endpoint. Default: public devnet. */
  readonly VITE_RPC_URL?: string;
  /** WebSocket endpoint, if it is not the RPC URL with ws(s)://. */
  readonly VITE_WS_URL?: string;
  /** Wallet Standard chain. Default: solana:devnet. */
  readonly VITE_CHAIN?: string;
  /** Mint to fill in. */
  readonly VITE_MINT?: string;
}
