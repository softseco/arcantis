// RPC "subscriptions" answered by polling HTTP instead of a websocket.
//
// @solana/kit confirms a transaction by listening for signature and slot notifications. The public
// devnet websocket drops connections under load, so the playground answers those two subscriptions
// by asking the HTTP endpoint about once a slot (400 ms), so that a transfer in one transaction shows
// as confirmed as soon as it is. Same shapes, no socket.

const ORDER = { processed: 0, confirmed: 1, finalized: 2 };

const nap = (ms, signal) =>
  new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(t); resolve(); }, { once: true });
  });

export function createPollingSubscriptions(rpc, { intervalMs = 400 } = {}) {
  return {
    signatureNotifications(signature, { commitment = "confirmed" } = {}) {
      return {
        async subscribe({ abortSignal }) {
          return (async function* () {
            while (!abortSignal?.aborted) {
              try {
                const { value } = await rpc.getSignatureStatuses([signature]).send({ abortSignal });
                const status = value[0];
                if (status && (status.err || ORDER[status.confirmationStatus] >= ORDER[commitment])) {
                  yield { context: { slot: status.slot }, value: { err: status.err ?? null } };
                  return;
                }
              } catch (err) {
                if (abortSignal?.aborted) return;
              }
              await nap(intervalMs, abortSignal);
            }
          })();
        },
      };
    },
    slotNotifications() {
      return {
        async subscribe({ abortSignal }) {
          return (async function* () {
            while (!abortSignal?.aborted) {
              try {
                const slot = await rpc.getSlot({ commitment: "confirmed" }).send({ abortSignal });
                yield { parent: slot - 1n, root: slot, slot };
              } catch (err) {
                if (abortSignal?.aborted) return;
              }
              await nap(intervalMs * 2, abortSignal);
            }
          })();
        },
      };
    },
  };
}
