"use client";

import { useEffect, useRef, useState } from "react";
import { Trace } from "@/components/Trace";
import { VerdictCard } from "@/components/VerdictCard";
import { API_URL, streamEvents } from "@/lib/sse";
import type { AgentEvent, TraceStep, Verdict } from "@/lib/types";

const MAX_CHARS = 4000;
const EXAMPLES: { label: string; text: string }[] = [
  {
    label: "Bank alert",
    text: "MAYBANK: Your acc has been suspended due to suspicious activity. Verify now to avoid permanent lock: http://maybank2u-secure-verify.com/login",
  },
  {
    label: "Parcel",
    text: "POS LAJU: Your parcel is on hold at our warehouse due to an incomplete address. Pay RM1.99 redelivery fee to reschedule: poslaju-redeliver.site/my",
  },
  {
    label: "LHDN",
    text: "LHDN NOTICE: Our records show outstanding tax arrears of RM3,212.00. Settle within 72 hours to avoid legal action. Pay here: https://lhdn-cukai-bayar.com/pay",
  },
  {
    label: "Real-looking alert",
    text: "Maybank: We have temporarily blocked your debit card due to a suspicious transaction. Please call our 24h Fraud Hotline at 03-5891 4744 or visit any branch.",
  },
];

interface ChatTurn {
  role: "user" | "agent";
  text: string;
}

export default function Home() {
  const [message, setMessage] = useState("");
  const [steps, setSteps] = useState<TraceStep[]>([]);
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [notes, setNotes] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [engine, setEngine] = useState<string | null>(null);
  const [chat, setChat] = useState<ChatTurn[]>([]);
  const [question, setQuestion] = useState("");
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    fetch(`${API_URL}/api/health`)
      .then((r) => r.json())
      .then((h) => setEngine(h.engine ?? null))
      .catch(() => setEngine(null));
    return () => abortRef.current?.abort();
  }, []);

  function handleEvent(ev: AgentEvent, target: "check" | "ask") {
    switch (ev.type) {
      case "session":
        setSessionId(ev.session_id);
        if (ev.engine) setEngine(ev.engine);
        break;
      case "tool_call":
        setSteps((s) => [...s, { id: ev.id, name: ev.name, input: ev.input }]);
        break;
      case "tool_result":
        setSteps((s) => s.map((st) => (st.id === ev.id ? { ...st, result: ev.result } : st)));
        break;
      case "text":
        if (target === "ask") setChat((c) => [...c, { role: "agent", text: ev.text }]);
        else setNotes((n) => [...n, ev.text]);
        break;
      case "verdict":
        setVerdict(ev.verdict);
        break;
      case "error":
        setError(ev.message);
        break;
    }
  }

  async function runCheck() {
    const text = message.trim();
    if (!text || running) return;
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setSteps([]);
    setVerdict(null);
    setNotes([]);
    setError(null);
    setChat([]);
    setSessionId(null);
    setRunning(true);
    try {
      await streamEvents("/api/check", { message: text }, (ev) => handleEvent(ev, "check"), ctrl.signal);
    } catch (e) {
      if (!ctrl.signal.aborted) setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setRunning(false);
    }
  }

  async function ask() {
    const q = question.trim();
    if (!q || !sessionId || running) return;
    setQuestion("");
    setChat((c) => [...c, { role: "user", text: q }]);
    setRunning(true);
    try {
      await streamEvents("/api/ask", { session_id: sessionId, question: q }, (ev) => handleEvent(ev, "ask"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <main className="page">
      <header className="top">
        <h1>Scam Checker 🇲🇾</h1>
        <p>
          Paste a suspicious SMS, WhatsApp message or email. The agent checks the links, the domain&apos;s
          registration, the claimed organisation&apos;s real channels and known scam patterns, and shows every
          check it runs.
        </p>
      </header>

      <section className="card input-card" aria-label="Message to check">
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value.slice(0, MAX_CHARS))}
          placeholder="Paste the message here…"
          aria-label="Suspicious message"
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) runCheck();
          }}
        />
        <div className="input-row">
          <div className="examples">
            {EXAMPLES.map((ex) => (
              <button key={ex.label} className="chip" type="button" onClick={() => setMessage(ex.text)}>
                {ex.label}
              </button>
            ))}
          </div>
          <span className="spacer" />
          <span className="counter">
            {message.length}/{MAX_CHARS}
          </span>
          <button className="primary" onClick={runCheck} disabled={running || !message.trim()}>
            {running && !sessionId ? "Checking…" : running ? "Working…" : "Check message"}
          </button>
        </div>
        {error && <div className="error-box">{error}</div>}
      </section>

      <div className="grid">
        <section className="card" aria-label="Investigation trace">
          <h2 className="section-title">
            Investigation {running && <span className="spinner" aria-label="running" />}
            {engine && (
              <span className="pill engine" title="Which engine answered">
                {engine === "rules" ? "offline rules engine (no AI)" : "Claude agent"}
              </span>
            )}
          </h2>
          <Trace steps={steps} running={running} />
          {notes.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {notes.map((n, i) => (
                <p key={i} className="step-summary" style={{ color: "var(--muted)" }}>
                  {n}
                </p>
              ))}
            </div>
          )}
        </section>

        <section className="card" aria-label="Verdict">
          <h2 className="section-title">Verdict</h2>
          {verdict ? (
            <>
              <VerdictCard verdict={verdict} steps={steps} />
              {sessionId && engine === "rules" && (
                <p className="empty" style={{ marginTop: 14 }}>
                  Follow-up questions need the Claude agent. This server runs the offline rules engine because no
                  API key is configured.
                </p>
              )}
              {sessionId && engine !== "rules" && (
                <div className="chat">
                  <h3 className="section-title">Ask a follow-up</h3>
                  {chat.map((t, i) => (
                    <div key={i} className={`bubble ${t.role}`}>
                      {t.text}
                    </div>
                  ))}
                  <div className="ask-row">
                    <input
                      value={question}
                      maxLength={1000}
                      onChange={(e) => setQuestion(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && ask()}
                      placeholder="e.g. I already clicked the link, what now?"
                      aria-label="Follow-up question"
                    />
                    <button className="primary" onClick={ask} disabled={running || !question.trim()}>
                      Ask
                    </button>
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="empty">
              {running ? "Waiting for the checks to finish…" : "The verdict, with the evidence behind it, appears here."}
            </p>
          )}
        </section>
      </div>

      <footer className="foot">
        An aid, not an authority. If money was lost, call <strong>NSRC 997</strong> immediately. Messages are not
        stored. Links in your message are never opened in your browser; the server follows them safely.
      </footer>
    </main>
  );
}
