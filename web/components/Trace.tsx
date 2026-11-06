import type { TraceStep } from "@/lib/types";

const LABELS: Record<string, string> = {
  extract_entities: "Extract links, numbers & claims",
  check_domain: "Check domain",
  resolve_url_redirects: "Follow redirects (server-side)",
  lookup_official_contact: "Look up official channels",
  match_scam_pattern: "Compare with known scams",
  check_phone_number: "Check phone number",
};

function shortInput(input: Record<string, unknown>): string {
  // Inputs are shown as inert text: links from the message are never rendered clickable.
  const parts = Object.entries(input)
    .filter(([, v]) => v !== "" && v !== null && v !== undefined)
    .map(([k, v]) => {
      const s = String(v);
      return `${k}=${s.length > 70 ? s.slice(0, 70) + "…" : s}`;
    });
  return parts.join(", ");
}

export function Trace({ steps, running }: { steps: TraceStep[]; running: boolean }) {
  if (!steps.length) {
    return (
      <p className="empty">
        {running ? "Starting the investigation…" : "Every check the agent runs will appear here, live."}
      </p>
    );
  }
  return (
    <ol className="trace">
      {steps.map((s) => (
        <li key={s.id} className="step">
          <div className="step-head">
            <span className="step-name">{s.name}</span>
            {s.result ? (
              <span className={`pill ${s.result.status}`}>{s.result.status}</span>
            ) : (
              <span className="pill running">
                <span className="spinner" aria-hidden /> running
              </span>
            )}
            <span className="step-input" title={LABELS[s.name]}>
              {LABELS[s.name]}
            </span>
          </div>
          {s.name !== "extract_entities" && s.name !== "match_scam_pattern" && (
            <div className="step-input">{shortInput(s.input)}</div>
          )}
          {s.result && (
            <>
              <p className="step-summary">{s.result.summary}</p>
              {s.result.signals.length > 0 && (
                <ul className="signals">
                  {s.result.signals.map((g, i) => (
                    <li key={i}>
                      <span className={`dot ${g.severity}`} aria-label={g.severity} />
                      <span>{g.detail}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </li>
      ))}
    </ol>
  );
}
