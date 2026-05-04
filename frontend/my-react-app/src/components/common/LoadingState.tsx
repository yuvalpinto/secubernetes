type LoadingStateProps = {
  message: string;
};

export function LoadingState({ message }: LoadingStateProps) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-500">
      {message}
    </div>
  );
}
