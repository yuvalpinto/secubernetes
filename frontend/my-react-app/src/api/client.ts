import { API_BASE } from "./config";

export class ApiRequestError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
  }
}

export async function apiGet<T>(path: string, errorLabel: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`);

  if (!res.ok) {
    throw new ApiRequestError(`${errorLabel} request failed: ${res.status}`, res.status);
  }

  return res.json() as Promise<T>;
}
