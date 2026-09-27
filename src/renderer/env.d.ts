import type { BlazmaApi } from '../shared/api';

declare global {
  interface Window {
    blazma: BlazmaApi;
  }
}

export {};
