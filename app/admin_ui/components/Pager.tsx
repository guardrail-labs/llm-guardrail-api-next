import React from "react";

export function Pager({
  nextCursor,
  prevCursor,
  onPage,
}: {
  nextCursor?: string | null;
  prevCursor?: string | null;
  onPage: (dir: "next" | "prev", cursor: string) => void;
}) {
  return (
    <div className="flex gap-2 items-center">
      <button
        disabled={!prevCursor}
        className="px-3 py-1 rounded-lg border disabled:opacity-50"
        onClick={() => prevCursor && onPage("prev", prevCursor)}
      >
        ← Newer
      </button>
      <button
        disabled={!nextCursor}
        className="px-3 py-1 rounded-lg border disabled:opacity-50"
        onClick={() => nextCursor && onPage("next", nextCursor)}
      >
        Older →
      </button>
    </div>
  );
}
