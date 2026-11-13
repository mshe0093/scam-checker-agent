import { useState } from "react";
import type { Contact, TraceStep, Verdict } from "@/lib/types";

const LABEL: Record<Verdict["verdict"], string> = {
  likely_scam: "Likely scam",
  suspicious: "Suspicious",
  likely_legitimate: "Likely legitimate",
  insufficient_information: "Not enough to judge",
};
const ICON = { fail: "✗", warn: "!", pass: "✓", unverified: "?" } as const;

interface OfficialInfo {
  org?: string;
  contacts: Contact[];
  generic: Contact[];
}

/** Official channels come only from lookup_official_contact results, never from the model's text. */
function officialFrom(steps: TraceStep[]): OfficialInfo {
  const info: OfficialInfo = { contacts: [], generic: [] };
  for (const s of steps) {
    if (s.name !== "lookup_official_contact" || !s.result) continue;
    const ev = s.result.evidence as { org?: string; contacts?: Contact[]; generic_reporting?: Contact[] };
    if (ev.org && !info.org) {
      info.org = ev.org;
      info.contacts = ev.contacts ?? [];
    }
    if (!info.generic.length) info.generic = ev.generic_reporting ?? [];
  }
  return info;
}

function ContactLine({ c }: { c: Contact }) {
  const isUrl = c.value.startsWith("https://");
  return (
    <li>
      {c.label}:{" "}
      {isUrl ? (
        <a href={c.value} target="_blank" rel="noopener noreferrer">
          {c.value.replace("https://", "")}
        </a>
      ) : (
        <strong>{c.value}</strong>
      )}{" "}
      <span className="tag">
        (
        <a href={c.source_url} target="_blank" rel="noopener noreferrer">
          {c.verification.replace("_", " ")}
        </a>
        )
      </span>
    </li>
  );
}

/** A short warning to forward to family. Built server-side from the verdict and the dataset only,
 * so it never repeats the scam's own links. */
function SharePanel({ share }: { share: { en: string; ms: string } }) {
  const [lang, setLang] = useState<"en" | "ms">("en");
  const [copied, setCopied] = useState(false);
  const text = share[lang];
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };
  return (
    <div className="share">
      <div className="share-head">
        <h3 className="section-title">Share this warning</h3>
        <div className="share-lang" role="group" aria-label="Language">
          <button type="button" aria-pressed={lang === "en"} onClick={() => setLang("en")}>
            English
          </button>
          <button type="button" aria-pressed={lang === "ms"} onClick={() => setLang("ms")}>
            Bahasa Melayu
          </button>
        </div>
      </div>
      <pre className="share-text">{text}</pre>
      <div className="share-actions">
        <button type="button" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
        <a
          className="whatsapp"
          href={`https://wa.me/?text=${encodeURIComponent(text)}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          Send on WhatsApp
        </a>
      </div>
    </div>
  );
}

export function VerdictCard({ verdict, steps }: { verdict: Verdict; steps: TraceStep[] }) {
  const official = officialFrom(steps);
  return (
    <div>
      <div className={`verdict-banner v-${verdict.verdict}`} role="status">
        <span className="label">{LABEL[verdict.verdict]}</span>
        <span className="conf">({verdict.confidence} confidence)</span>
        <p>{verdict.headline}</p>
      </div>

      {verdict.floor_applied && (
        <div className="floor">
          <strong>Safety floor applied.</strong> The model leaned towards &ldquo;likely legitimate&rdquo;, but
          hard evidence overrides it:
          <ul>
            {verdict.floor_applied.reasons.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {verdict.findings.length > 0 && (
        <>
          <h3 className="section-title">Findings</h3>
          <ul className="findings">
            {verdict.findings.map((f, i) => (
              <li key={i}>
                <span className={`icon ${f.outcome}`} aria-label={f.outcome}>
                  {ICON[f.outcome]}
                </span>
                <span>
                  <strong>{f.check}</strong> — {f.detail}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      {verdict.recommended_actions.length > 0 && (
        <>
          <h3 className="section-title">What to do</h3>
          <ul className="actions">
            {verdict.recommended_actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </>
      )}

      {verdict.share && <SharePanel share={verdict.share} />}

      {(official.contacts.length > 0 || official.generic.length > 0) && (
        <div className="contacts">
          {official.org && official.contacts.length > 0 && (
            <>
              <h4>Official channels for {official.org}</h4>
              <ul>
                {official.contacts.map((c, i) => (
                  <ContactLine key={i} c={c} />
                ))}
              </ul>
            </>
          )}
          {official.generic.length > 0 && (
            <>
              <h4 style={{ marginTop: official.contacts.length ? 10 : 0 }}>Report or check</h4>
              <ul>
                {official.generic.map((c, i) => (
                  <ContactLine key={i} c={c} />
                ))}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}
