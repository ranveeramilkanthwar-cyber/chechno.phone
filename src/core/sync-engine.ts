/**
 * PrivaIndia Isomorphic Web <-> Mobile Synchronization Engine
 * Aligned with Blueprint Section 3.1 & Sub-50ms reactive delta broadcast.
 */
import { SyncEventPayload } from '../types/dpdp';

export type SyncListener = (payload: SyncEventPayload) => void;

class PrivaSyncBus {
  private channel: BroadcastChannel | null = null;
  private listeners: Set<SyncListener> = new Set();
  private ws: WebSocket | null = null;
  private isConnected: boolean = false;

  constructor() {
    if (typeof window !== 'undefined' && 'BroadcastChannel' in window) {
      this.channel = new BroadcastChannel('privaindia_sync_bus');
      this.channel.onmessage = (event) => {
        this.notify(event.data);
      };
    }
  }

  public subscribe(listener: SyncListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  public broadcast(payload: SyncEventPayload): void {
    // Notify in-process listeners
    this.notify(payload);

    // Broadcast across browser tabs / frames
    if (this.channel) {
      this.channel.postMessage(payload);
    }

    // Broadcast over WebSocket if connected
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(payload));
    }
  }

  private notify(payload: SyncEventPayload): void {
    this.listeners.forEach((listener) => {
      try {
        listener(payload);
      } catch (err) {
        console.error('Error in sync listener:', err);
      }
    });
  }
}

export const privaSyncBus = new PrivaSyncBus();
