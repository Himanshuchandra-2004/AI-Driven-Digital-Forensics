/** Simple animated dropdown section (native <details>). */
import type { ReactNode } from 'react';
import { ChevronDown } from 'lucide-react';

export default function Accordion({ title, count, defaultOpen = false, children }: { title: string; count?: number; defaultOpen?: boolean; children: ReactNode }) {
  return (
    <details className="acc" open={defaultOpen}>
      <summary>
        <span>{title}{count !== undefined && <em>{count}</em>}</span>
        <ChevronDown className="w-4 h-4 acc-chevron" />
      </summary>
      <div className="acc-body">{children}</div>
    </details>
  );
}
