import { useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import Logo from "./Logo";
import Icon from "./Icons";

/* Split the assistant's markdown on its own ## / ### headings (outside code fences)
   so known sections can be styled. Only real content is rendered; nothing is added. */
function splitSections(md) {
  const out = [];
  let cur = { heading: null, level: 0, body: [] };
  let fence = false;
  for (const line of md.split("\n")) {
    if (/^\s*```/.test(line)) fence = !fence;
    const m = !fence && line.match(/^(#{2,3})\s+(.+?)\s*$/);
    if (m) {
      out.push(cur);
      cur = { heading: m[2], level: m[1].length, body: [] };
    } else {
      cur.body.push(line);
    }
  }
  out.push(cur);
  return out.filter((s) => s.heading || s.body.join("").trim());
}

const KINDS = [
  [/^cyberlens knowledge base/i, "kb", "shieldCheck"],
  [/^general guidance/i, "general", "info"],
  [/^remediation command/i, "command", "terminal"],
  [/^remediation/i, "remediation", "wrench"],
  [/^risk|^severity/i, "risk", "alert"],
  [/^affected/i, "product", "box"],
];

function sectionKind(heading) {
  if (!heading) return ["plain", null];
  const hit = KINDS.find(([re]) => re.test(heading));
  return hit ? [hit[1], hit[2]] : ["plain", null];
}

const textOf = (node) =>
  typeof node === "string" ? node
  : Array.isArray(node) ? node.map(textOf).join("")
  : node?.props ? textOf(node.props.children) : "";

function CodeBlock({ children }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(textOf(children).replace(/\n$/, ""));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard unavailable */ }
  };
  return (
    <div className="code-block">
      <div className="code-bar">
        <span>Command</span>
        <button type="button" className="copy-button" onClick={copy}>{copied ? "Copied" : "Copy"}</button>
      </div>
      <pre>{children}</pre>
    </div>
  );
}

const mdComponents = {
  pre: ({ children }) => <CodeBlock>{children}</CodeBlock>,
  table: ({ children }) => <div className="table-wrap"><table>{children}</table></div>,
  a: ({ children, href }) => <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>,
};

function MessageBubble({ message }) {
  const isUser = message.role === "user";

  if (isUser) {
    return (
      <div className="message-row query-row">
        <div className="query-label">You</div>
        <p className="query-text">{message.content}</p>
      </div>
    );
  }

  const isError = Boolean(message.isError);
  let lane = "none";

  return (
    <article className={`message-row report ${isError ? "report-error" : ""}`}>
      <header className="report-head">
        <span className="report-mark"><Logo size={18} /></span>
        <strong>CyberLens AI</strong>
        <span className="report-sub">{isError ? "Request failed" : "Security analysis"}</span>
      </header>

      <div className="message-content">
        {isError ? (
          <p>{message.content}</p>
        ) : (
          splitSections(message.content).map((s, i) => {
            const [kind, icon] = sectionKind(s.heading);
            if (s.level === 2) lane = kind === "kb" || kind === "general" ? kind : "none";
            const H = s.level === 2 ? "h2" : "h3";
            return (
              <section key={i} className={`sec sec-${kind} lane-${lane}`}>
                {s.heading && (
                  <H>{icon && <span className="sec-icon"><Icon name={icon} size={s.level === 2 ? 17 : 15} /></span>}{s.heading}</H>
                )}
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
                  {s.body.join("\n")}
                </ReactMarkdown>
              </section>
            );
          })
        )}
      </div>
    </article>
  );
}

export default MessageBubble;