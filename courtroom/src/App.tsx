import { useEffect, useState } from "react";
import { Api, takeTokenFromUrl, type Blotter, type CaseItem } from "./api";
import { isMuted, playGavel, setMuted } from "./sounds";

// Read the token once, before the first render, so it is never left in the address bar.
const token = takeTokenFromUrl();

export function App() {
  const [api] = useState(() => (token ? new Api(token) : null));
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [blotter, setBlotter] = useState<Blotter | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [muted, setMutedState] = useState(isMuted());
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    if (!api) return;
    try {
      setCases(await api.listCases());
      setBlotter(await api.blotter());
      setError(null);
    } catch {
      setError("Could not load cases. Is the courtroom running with the right token?");
    }
  };

  useEffect(() => {
    void refresh();
    // Load once on start. refresh is recreated each render, so it is left out on purpose.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!api) {
    return <main className="page"><h1>Courtroom</h1><p>Open the link printed by the courtroom command.</p></main>;
  }

  const current = cases.find((c) => c.case_id === selected) ?? null;

  const decide = async (action: "release" | "convict") => {
    if (!current) return;
    try {
      await api.decide(current.case_id, action);
      playGavel();
      await refresh();
    } catch {
      setError("The decision was not recorded. Try again.");
    }
  };

  return (
    <main className="page">
      <header className="top">
        <h1>Courtroom</h1>
        {blotter && <span className="rank" data-testid="rank">{blotter.rank.name}</span>}
        <button
          className="mute"
          aria-label={muted ? "Unmute sounds" : "Mute sounds"}
          onClick={() => {
            setMuted(!muted);
            setMutedState(!muted);
          }}
        >
          {muted ? "Sound off" : "Sound on"}
        </button>
      </header>
      {error && <p role="alert" className="error">{error}</p>}
      <div className="layout">
        <section aria-label="Timeline">
          <h2>Timeline</h2>
          <ul className="timeline">
            {cases.map((c) => (
              <li key={c.case_id}>
                <button
                  data-testid="case-row"
                  className={c.case_id === selected ? "row selected" : "row"}
                  onClick={() => setSelected(c.case_id)}
                >
                  <span className="id">{c.case_id}</span>
                  <span className={`verdict ${c.verdict}`}>{c.verdict}</span>
                  <span className="time">{c.timestamp}</span>
                  <span className="status">{c.status}</span>
                </button>
              </li>
            ))}
          </ul>
          {cases.length === 0 && <p>No cases yet.</p>}
          {blotter && (
            <>
              <h2>Police Blotter</h2>
              <ul className="blotter">
                {blotter.weeks.map((w) => (
                  <li key={w.week} data-testid="blotter-week">
                    Week of {w.week}: {w.cases} cases, {w.deny} deny, {w.convicted} convicted, {w.released} released
                  </li>
                ))}
              </ul>
              <h2>Wanted</h2>
              <ul className="wanted" data-testid="wanted">
                {blotter.wanted.map((c) => (
                  <li key={c.case_id}>{c.case_id}</li>
                ))}
              </ul>
            </>
          )}
        </section>
        <section aria-label="Case">
          {current ? (
            <article data-testid="mugshot" className="mugshot">
              <div className="stamp">{current.verdict}</div>
              <h2>{current.case_id}</h2>
              <p>Tool: <strong>{current.tool_name}</strong></p>
              <p>Reason: {current.reason}</p>
              <pre>{current.command}</pre>
              <p>Status: {current.status}</p>
              <div className="buttons">
                <button onClick={() => void decide("convict")}>Convict</button>
                <button onClick={() => void decide("release")}>Release</button>
              </div>
            </article>
          ) : (
            <p>Pick a case from the timeline.</p>
          )}
        </section>
      </div>
    </main>
  );
}
