export type ApiListResponse<T> = {
  items: T[];
  count: number;
};

export type MongoObjectId = {
  $oid?: string;
};

export type TimeRange = "15m" | "1h" | "6h" | "24h" | "7d" | "all";
