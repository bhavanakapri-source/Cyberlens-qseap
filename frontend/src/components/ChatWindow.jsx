import { useEffect, useRef, useState } from "react";
import MessageBubble from "./MessageBubble";
import InputBox from "./InputBox";
import Logo from "./Logo";
import Icon from "./Icons";

const CARDS = [
  { icon: "search", title: "CVE Investigation", desc: "Investigate a specific CVE", prompt: "How do I fix CVE-2021-36934?" },
  { icon: "radar", title: "Threat Analysis", desc: "Find exploitable vulnerabilities", prompt: "Which Windows vulnerabilities are exploitable?" },
  { icon: "wrench", title: "Remediation", desc: "Find the right fix", prompt: "How do I remediate a Linux vulnerability?" },
  { icon: "layers", title: "Vulnerability Analysis", desc: "Understand the risk", prompt: "What is the risk of this CVE?" },
];

/* UI-only status text; it does not reflect real backend stages. */
const STATUS = ["Analyzing query…", "Searching vulnerability knowledge…", "Preparing security guidance…"];

function LoadingIndicator() {
  const [i, setI] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setI((n) => Math.min(n + 1, STATUS.length - 1)), 2500);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="message-row analyzing" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true"><Logo size={16} /></span>
      <div>
        <strong>CyberLens AI</strong>
        <span>{STATUS[i]}</span>
      </div>
      <span className="scanline" aria-hidden="true" />
    </div>
  );
}

function ChatWindow({ messages, loading, onSend, onMenu, title, user }) {
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  const initial = (user?.name || user?.email || "?").trim().charAt(0).toUpperCase();
  const empty = messages.length === 0 && !loading;

  return (
    <main className="chat-window">
      <header className="chat-header">
        <button type="button" className="icon-button menu-button" onClick={onMenu} aria-label="Open menu">
          <Icon name="menu" />
        </button>
        <div className="header-titles">
          <h2>{title || "New investigation"}</h2>
          <span>CyberLens · Vulnerability Intelligence</span>
        </div>
        <div className="header-user" title={user?.email}>
          <span className="user-avatar" aria-hidden="true">{initial}</span>
          <span className="header-user-name">{user?.name}</span>
        </div>
      </header>

      <div className="messages-area">
        {empty ? (
          <div className="command-center">
            <div className="cc-mark"><Logo size={40} /></div>
            <h1>Vulnerability Intelligence</h1>
            <p>Investigate CVEs. Understand risk.<br />Get grounded remediation guidance.</p>
            <div className="card-grid">
              {CARDS.map((c) => (
                <button type="button" key={c.title} className="inv-card" onClick={() => onSend(c.prompt)}>
                  <span className="inv-icon"><Icon name={c.icon} size={20} /></span>
                  <strong>{c.title}</strong>
                  <span className="inv-desc">{c.desc}</span>
                  <code>{c.prompt}</code>
                </button>
              ))}
            </div>
          </div>
        ) : (
          <div className="messages-container" role="log" aria-live="polite">
            {messages.map((m) => <MessageBubble key={m.id} message={m} />)}
            {loading && <LoadingIndicator />}
            <div ref={endRef} />
          </div>
        )}
      </div>

      <InputBox onSend={onSend} disabled={loading} />
    </main>
  );
}

export default ChatWindow;